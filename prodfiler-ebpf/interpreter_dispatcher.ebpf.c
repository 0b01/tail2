// This file contains the code and map definitions that are shared between
// the tracers, as well as a dispatcher program that can be attached to a
// perf event and will call the appropriate tracer for a given process

#undef asm_volatile_goto
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

#include "bpfdefs.h"
#ifdef TESTING
  #include <sys/types.h>
  #include <unistd.h>
#endif
#include "types.h"
#include "tracemgmt.h"

// Begin shared maps

// Per-CPU record of the stack being built and meta-data on the building process
bpf_map_def SEC("maps/per_cpu_records") per_cpu_records = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(PerCPURecord),
  .max_entries = 1,
};

// Per-CPU frame stack used as temporary store to unwind the frames
bpf_map_def SEC("maps/per_cpu_frame_list") per_cpu_frame_list = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(FrameList),
  .max_entries = MAX_FRAME_LISTS,
};

// hash_to_framelist is used to report new call stacks from the kernel
// to the user space side.
// The max_entries in this map is the upper limit on the number of FrameStacks in
// new traces that we can have observed in eBPF but not yet processed by userland.
// If we are generating all new traces, all the time, then to avoid losing traces this
// must at least equal:
//
// MONITOR_INTERVAL * SAMPLING_FREQ * NUM_CORES * MAX_FRAME_LISTS
//
// Where MONITOR_INTERVAL is the interval at which userland is processing this
// map, SAMPLING_FREQ is the frequency at which the eBPF tracer samples,
// NUM_CORES is the number of cores on the machine, and MAX_FRAME_LISTS
// is the maximum number of FrameStacks that may be used to represent a single trace.
bpf_map_def SEC("maps/hash_to_framelist") hash_to_framelist = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(FrameListID),
  .value_size = sizeof(FrameList),
  // Size is set from Go at runtime
  .max_entries = 16384,
};

// hash_to_trace maps from a trace hash to a trace
bpf_map_def SEC("maps/hash_to_trace") hash_to_trace = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(TraceHash),
  .value_size = sizeof(Trace),
  // Size is set from Go at runtime
  .max_entries = 10240,
};

// hash_to_count maps from a trace hash to a count for that trace
bpf_map_def SEC("maps/hash_to_count") hash_to_count = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(TraceHash),
  .value_size = sizeof(u32),
  // Size is set from Go at runtime
  .max_entries = 10240,
};

// known_traces indicates if a particular trace hash has been encountered before
bpf_map_def SEC("maps/known_traces") known_traces = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(TraceHash),
  .value_size = sizeof(bool),
  // Size is set from Go at runtime
  .max_entries = 32768,
};

// metrics maps metric ID to a value
bpf_map_def SEC("maps/metrics") metrics = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(u64),
  .max_entries = metricID_Max,
};

// progs maps from a program ID to an eBPF program
bpf_map_def SEC("maps/progs") progs = {
  .type = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(u32),
  .max_entries = NUM_TRACER_PROGS,
};

// report_pid_events represents the communication channel between eBPF and user space to
// notify user space about PID related events.
// As key the CPU number is used and the value represents a perf event file descriptor.
// We use 0 as the number of max entries for this map as at load time it will be replaced
// by the number of possible CPUs. At the same time this will then also define the number
// of perf event rings that are used for this map.
bpf_map_def SEC("maps/report_pid_events") report_pid_events = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(u32),
  .max_entries = 0,
};

// reported_pids is a map that holds pid information recently reported to user space.
//
// We use this map to avoid sending multiple notifications for the same process to user space. The
// key represents the PID of the process and value holds the timestamp of the moment we write into
// this map. When sizing this map, we are thinking about the maximum number of unique PIDs
// that could be stored, without immediately being removed, that we would
// like to support.
bpf_map_def SEC("maps/reported_pids") reported_pids = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(u32),
  .value_size = sizeof(u64),
  .max_entries = 32768,
};

// The native unwinder needs to be able to determine how each mapping should be unwound.
//
// This map contains data to help the native unwinder translate from a virtual address in a given
// process. It contains information of the unwinder program to use, how to convert the virtual
// address to relative address, and what executable file is in question.
bpf_map_def SEC("maps/pid_page_to_mapping_info") pid_page_to_mapping_info = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(PIDPage),
  .value_size = sizeof(PIDPageMappingInfo),
  .max_entries = 524288, // 2^19
  .map_flags = BPF_F_NO_PREALLOC,
};

// report_unknown_pc is used to inform userspace about an unknown PC for a pid.
bpf_map_def SEC("maps/report_unknown_pc") report_unknown_pc = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(u32),
  .value_size = sizeof(u64),
  .max_entries = 4096,
};

// defer_pc is a map that holds reported PID/PC information. It holds PID/PC
// combinations that can not be resolved to a executable memory mapping.
bpf_map_def SEC("maps/defer_pc") defer_pc = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(UnknownPC),
  .value_size = sizeof(bool),
  .max_entries = 32768,
};

// inhibit_events map is used to inhibit sending "new traces" events.
// Only one event needs to be sent as it's a manual trigger to start proccessing
// traces early. The HA will reset this entry once it has reacted to the trigger,
// so next event is sent when needed.
// Currently only available for PID_EVENT_TYPE_TRACES_FOR_SYMBOLIZATION, and
// PID_EVENT_TYPE_UNKNOWN_PC.
// NOTE: Update .max_entries if additional event types are added. The value should
// equal the number of different event types using this mechanism.
bpf_map_def SEC("maps/inhibit_events") inhibit_events = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(u32),
  .value_size = sizeof(bool),
  .max_entries = 2,
};

// End shared maps

// report_framelist loops over one FrameList and reports all its frames to userspace via
// the hash_to_framelist map. On the userspace side frame lists associated with a particular
// trace can be identified by the trace_hash, and the order of the frame lists is given by the
// list_index.
static inline __attribute__((__always_inline__))
int report_framelist(FrameList *store, TraceHash trace_hash, u8 list_index) {
  FrameListID frameListID = {};
  frameListID.hash = trace_hash;
  frameListID.list_index = list_index;
  FrameList list = {};

#pragma unroll
  for (int i = 0; i < MAX_FRAME_LIST_SIZE; i++) {
    list.files[i] = store->files[i];
    list.linenos[i] = store->linenos[i];
    list.frame_types[i] = store->frame_types[i];
  }
  return bpf_map_update_elem(&hash_to_framelist, &frameListID, &list, BPF_NOEXIST);
}

// report_frames loops over all FrameLists and pushes these stacks
// to the user space side using the report_framelist function.
//
// We manually unroll the loop over the FrameLists in per_cpu_frame_list to
// satisfy the requirements of the compiler and eBPF verifier.
//
// The number of manually unrolled unwinds is:
// MAX_FRAME_UNWINDS / MAX_FRAME_LIST_SIZE
static inline __attribute__((__always_inline__))
int report_frames(int stack_len, TraceHash trace_hash) {
  FrameList *list;

  if (stack_len == 0) {
    // There are no user space frames to report.
    return 0;
  }

  // First FrameList
  int i = 0;
  list = bpf_map_lookup_elem(&per_cpu_frame_list, &i);
  if (!list) {
    return -1;
  }
  if (report_framelist(list, trace_hash, i)) {
    return -1;
  }

  // Second FrameList
  i = 1;
  if (stack_len <= (i*MAX_FRAME_LIST_SIZE)) {
    return 0;
  }
  list = bpf_map_lookup_elem(&per_cpu_frame_list, &i);
  if (!list) {
    return -1;
  }
  if (report_framelist(list, trace_hash, i)) {
    return -1;
  }

  // Third FrameList
  i = 2;
  if (stack_len <= (i*MAX_FRAME_LIST_SIZE)) {
    return 0;
  }
  list = bpf_map_lookup_elem(&per_cpu_frame_list, &i);
  if (!list) {
    return -1;
  }
  if (report_framelist(list, trace_hash, i)) {
    return -1;
  }

  // Fourth FrameList
  i = 3;
  if (stack_len <= (i*MAX_FRAME_LIST_SIZE)) {
    return 0;
  }
  list = bpf_map_lookup_elem(&per_cpu_frame_list, &i);
  if (!list) {
    return -1;
  }
  if (report_framelist(list, trace_hash, i)) {
    return -1;
  }

  // Fifth FrameList
  i = 4;
  if (stack_len <= (i*MAX_FRAME_LIST_SIZE)) {
    return 0;
  }
  list = bpf_map_lookup_elem(&per_cpu_frame_list, &i);
  if (!list) {
    return -1;
  }
  if (report_framelist(list, trace_hash, i)) {
    return -1;
  }

  // Sixth FrameList
  i = 5;
  if (stack_len <= (i*MAX_FRAME_LIST_SIZE)) {
    return 0;
  }
  list = bpf_map_lookup_elem(&per_cpu_frame_list, &i);
  if (!list) {
    return -1;
  }
  if (report_framelist(list, trace_hash, i)) {
    return -1;
  }

  return 0;
}

// hash_frame_list computes the hash for a given FrameList.
static inline __attribute__((__always_inline__))
TraceHash hash_frame_list(FrameList *list, u8 elements) {
  TraceHash h = 0;

#pragma unroll
  for (u8 i = 0; i < MAX_FRAME_LIST_SIZE; i++) {
    if (i < elements) {
      h += (list->files[i] * FRAME_CONTENT_PRIME[i]);
      h += (list->linenos[i] * FRAME_CONTENT_PRIME[i]);
    }
  }

  return h;
}

// hash_trace loops over all FrameLists to calculate the hash of the entire trace.
//
// Manually unroll the loop over the FrameLists in per_cpu_frame_list to satisfy
// the requirements of the compiler and eBPF verifier.
//
// The number of manually unrolled unwinds is:
// MAX_FRAME_UNWINDS / MAX_FRAME_LIST_SIZE
static inline __attribute__((__always_inline__))
TraceHash hash_trace(u32 stack_len, s32 kernel_stack_id) {
  TraceHash h = kernel_stack_id;

  FrameList *frame_list;
  u8 elements = 0;

  unsigned num_frame_lists = stack_len / MAX_FRAME_LIST_SIZE;

  // First FrameList
  unsigned i = 0;
  frame_list = bpf_map_lookup_elem(&per_cpu_frame_list, &i);
  if (!frame_list) {
    return -1;
  }
  elements = ((i+1)*MAX_FRAME_LIST_SIZE <= stack_len)?
    MAX_FRAME_LIST_SIZE : (stack_len % MAX_FRAME_LIST_SIZE);
  h += (hash_frame_list(frame_list, elements) * FRAME_LIST_PRIME_0);

  // Second FrameList
  i = 1;
  if (i > num_frame_lists) {
    return h;
  }
  frame_list = bpf_map_lookup_elem(&per_cpu_frame_list, &i);
  if (!frame_list) {
    return -1;
  }
  elements = ((i+1)*MAX_FRAME_LIST_SIZE <= stack_len)?
    MAX_FRAME_LIST_SIZE : (stack_len % MAX_FRAME_LIST_SIZE);
  h += (hash_frame_list(frame_list, elements) * FRAME_LIST_PRIME_1);

  // Third FrameList
  i = 2;
  if (i > num_frame_lists) {
    return h;
  }
  frame_list = bpf_map_lookup_elem(&per_cpu_frame_list, &i);
  if (!frame_list) {
    return -1;
  }
  elements = ((i+1)*MAX_FRAME_LIST_SIZE <= stack_len)?
    MAX_FRAME_LIST_SIZE : (stack_len % MAX_FRAME_LIST_SIZE);
  h += (hash_frame_list(frame_list, elements) * FRAME_LIST_PRIME_2);

  // Fourth FrameList
  i = 3;
  if (i > num_frame_lists) {
    return h;
  }
  frame_list = bpf_map_lookup_elem(&per_cpu_frame_list, &i);
  if (!frame_list) {
    return -1;
  }
  elements = ((i+1)*MAX_FRAME_LIST_SIZE <= stack_len)?
    MAX_FRAME_LIST_SIZE : (stack_len % MAX_FRAME_LIST_SIZE);
  h += (hash_frame_list(frame_list, elements) * FRAME_LIST_PRIME_3);

  //  Fifth FrameList
  i = 4;
  if (i > num_frame_lists) {
    return h;
  }
  frame_list = bpf_map_lookup_elem(&per_cpu_frame_list, &i);
  if (!frame_list) {
    return -1;
  }
  elements = ((i+1)*MAX_FRAME_LIST_SIZE <= stack_len)?
    MAX_FRAME_LIST_SIZE : (stack_len % MAX_FRAME_LIST_SIZE);
  h += (hash_frame_list(frame_list, elements) * FRAME_LIST_PRIME_4);

  // Sixth FrameList
  i = 5;
  if (i > num_frame_lists) {
    return h;
  }
  frame_list = bpf_map_lookup_elem(&per_cpu_frame_list, &i);
  if (!frame_list) {
    return -1;
  }
  elements = ((i+1)*MAX_FRAME_LIST_SIZE <= stack_len)?
    MAX_FRAME_LIST_SIZE : (stack_len % MAX_FRAME_LIST_SIZE);
  h += (hash_frame_list(frame_list, elements) * FRAME_LIST_PRIME_5);

  return h;
}

// increment_hash_counter increments the count we have for
// a given trace_hash.
static inline __attribute__((__always_inline__))
int increment_hash_counter(TraceHash trace_hash) {
  u32 new_count = 1;
  if (bpf_map_update_elem(&hash_to_count, &trace_hash, &new_count, BPF_NOEXIST)) {
    u32 *count = bpf_map_lookup_elem(&hash_to_count, &trace_hash);
    if (count) {
      // Entry already exists
      ATOMIC_ADD(count, 1);
      DEBUG_PRINT("Incremented trace count for trace 0x%llx", trace_hash);
      return 0;
    }
    DEBUG_PRINT("increment_hash_counter failed to make new entry in hash_to_count map");
    return -1;
  }

  DEBUG_PRINT("Set trace count for trace 0x%llx to 1", trace_hash);
  return 0;
}

// update_trace_count reports new frames to the user space side if needed
// and increments the count for the given trace.
static inline __attribute__((__always_inline__))
int update_trace_count(struct bpf_perf_event_data *ctx, Trace *trace) {
  trace->hash = hash_trace(trace->stack_len, trace->kernel_stack_id);
  if (trace->hash == (TraceHash)-1) {
    DEBUG_PRINT("hash_trace() failed");
    increment_metric(metricID_ErrHashTrace);
    return -1;
  }

  // While hash_trace() calculates and returns the frame based part of the hash we need some
  // additional differentiator to not mix traces with the same frames but from different
  // processes. Adding more differentiators can increase the number of reported hashes from eBPF
  // to userspace and so can have an impact on the performance of the host agent.
  trace->hash += hash32(trace->pid);

  // The verifier on older kernels requires this parameter in a local variable
  TraceHash tmp_trace_hash = trace->hash;

  bool exists = bpf_map_lookup_elem(&known_traces, &tmp_trace_hash);
  if (!exists) {
    // This trace is not cached
    bool sent = bpf_map_lookup_elem(&hash_to_trace, &tmp_trace_hash);
    if (!sent) {
      // We don't want to increment the metric multiple times for the same trace,
      // if processing for that trace in Go is pending.
      increment_metric(metricID_KnownTracesMiss);

      // This trace's frames have not been recently sent to userspace
      bpf_tail_call(ctx, &progs, PROG_REPORT_TRACE);
      DEBUG_PRINT("bpf_tail call failed for PROG_REPORT_TRACE in update_trace_count");
      return 0;
    }
  } else {
    increment_metric(metricID_KnownTracesHit);
  }

  increment_hash_counter(trace->hash);
  return 0;
}

SEC("perf_event/unwind_stop")
int unwind_stop(struct bpf_perf_event_data *ctx) {
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  Trace *trace = &record->trace;
  UnwindState *state = &record->state;
  switch (state->error_metric) {
  case -1:
    // No Error
    break;
  case metricID_UnwindNativeErrWrongTextSection:;
    // Instead of the exact PC we lookup the page size aligned PC and report
    // it, if it is not listed in the eBPF map defer_pc.
    // We use a page sized aligned PC to reduce the number of PCs in defer_pc,
    // but also to report fewer unknown PCs to user space via report_unknown_pc.
    // PCs can have any value within an executable memory mapping. But we assume
    // that memory mappings have at least the size of PAGE_SIZE.
    pid_t pid = trace->pid;
    u64 pc = state->pc;
    UnknownPC key = {};
    key.pid = (u32) pid;
    key.pc = pc & ~((u64)(PAGE_SIZE - 1));
    bool exists = true;

    if (!bpf_map_update_elem(&defer_pc, &key, &exists, BPF_NOEXIST)) {
      // Report a new PID/PC combination to user space.
      if (!bpf_map_update_elem(&report_unknown_pc, &pid, &pc, BPF_ANY)) {
        // Wake up the HA if needed
        DEBUG_PRINT("Unknown pc event sent (0x%lx)", (unsigned long) pc);
        pid_event_send_trigger(ctx, pid, PID_EVENT_TYPE_UNKNOWN_PC);
      } else {
        // In case of a failure we don't want to return here. We are still interested
        // in maintaining and updating our other eBPF maps.
        DEBUG_PRINT("Failure to report unknown pc 0x%lx", (unsigned long) pc);
      }
    }

    // Fallthrough to report the error
  default:
    increment_metric(state->error_metric);
  }

  if (trace->stack_len > 0 || trace->kernel_stack_id >= 0) {
    if (update_trace_count(ctx, trace)) {
      DEBUG_PRINT("update_trace_count failed");
      return -1;
    }
    DEBUG_PRINT("Trace count updated");
    return 0;
  }

  increment_metric(metricID_ErrEmptyStack);
  DEBUG_PRINT("unwind_stop called but the stack is empty");
  return 0;
}

// report_trace is an eBPF program that reports the current trace to user-space. It is called from
// unwind_stop (via update_trace_count), and it is its own program in order to deal with the eBPF
// program instruction limit.
//
// A trace is reported in three steps. First, the trace hash is written to the map of known traces.
// Second, the frames in the trace are reported via the report_frames function. Third, the Trace
// structure is reported to user-space via the hash_to_trace map. The trace structure mostly
// contains meta-data about a trace, such as the associated kernel stack ID, and the number of
// frames in the trace.
SEC("perf_event/report_trace")
int report_trace(struct bpf_perf_event_data *ctx) {
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  Trace *trace = &record->trace;
  TraceHash trace_hash = trace->hash;

  if (bpf_get_current_comm(&(trace->comm), sizeof(trace->comm)) < 0) {
    increment_metric(metricID_ErrBPFCurrentComm);
  }

  if (report_frames(trace->stack_len, trace_hash)) {
    DEBUG_PRINT("reporting frames for 0x%llx failed", trace_hash);
    increment_metric(metricID_ErrReportNewFrames);
    return 0;
  }

  // The eBPF verifier for kernel < 4.19 requires the eBPF map value to be on the stack.
  Trace trace_ = *trace;
  if (bpf_map_update_elem(&hash_to_trace, &trace_hash, &trace_, BPF_NOEXIST)) {
    DEBUG_PRINT("report_trace failed to update hash_to_trace map");
    return 0;
  }
  DEBUG_PRINT("Recorded trace contents for trace 0x%llx", trace_hash);

  if (record->ha_symbolization_needed) {
    pid_event_send_trigger(ctx, trace->pid, PID_EVENT_TYPE_TRACES_FOR_SYMBOLIZATION);
  }

  increment_hash_counter(trace_hash);

  return 0;
}

// trace_interpreter checks a given pid, if it is a known interpreted process.
// If so, its process unwinding is triggered.
static inline __attribute__((__always_inline__))
int trace_interpreter(struct pt_regs *ctx, u32 pid) {
  // Setup per-cpu trace environment
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record)
    return -1;

  Trace *trace = &record->trace;
  trace->pid = pid;

  // Check if this is a Perl process
  PerlProcInfo *perlinfo = bpf_map_lookup_elem(&perl_procs, &pid);
  if (perlinfo) {
    // Does not return
    bpf_tail_call(ctx, &progs, PROG_UNWIND_PERL);
    DEBUG_PRINT("bpf_tail call failed for PROG_UNWIND_PERL in trace_interpreter");
    return 0;
  }

  // Check if this is a Python process
  PyProcInfo *pyinfo = bpf_map_lookup_elem(&py_procs, &pid);
  if (pyinfo) {
    // Does not return
    bpf_tail_call(ctx, &progs, PROG_UNWIND_PYTHON);
    DEBUG_PRINT("bpf_tail call failed for PROG_UNWIND_PYTHON in trace_interpreter");
    return 0;
  }

  // Check if this is a Ruby process
  RubyProcInfo *rubyinfo = bpf_map_lookup_elem(&ruby_procs, &pid);
  if (rubyinfo) {
    // Does not return
    bpf_tail_call(ctx, &progs, PROG_UNWIND_RUBY);
    DEBUG_PRINT("bpf_tail call failed for PROG_UNWIND_RUBY in trace_interpreter");
    return 0;
  }

  // Check if this is a PHP process
  void **executor_globals = bpf_map_lookup_elem(&php_procs, &pid);
  if (executor_globals) {
    // Does not return
    bpf_tail_call(ctx, &progs, PROG_UNWIND_PHP);
    DEBUG_PRINT("bpf_tail call failed for PROG_UNWIND_PHP in trace_interpreter");

    return 0;
  }

  return 0;
}

SEC("perf_event/interpreter_tracer_entry")
int interpreter_tracer_entry(struct pt_regs *ctx) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  if (pid == 0) {
    return 0;
  }

  if (!pid_information_exists(ctx, pid)) {
    report_new_pid(ctx, pid);
    return 0;
  }

  trace_interpreter(ctx, (u32)pid);
  return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader
// to set the current running kernel version
u32 _version SEC("version") = 0xFFFFFFFE;

// tracepoint__sys_enter_read serves as dummy tracepoint so we can check if tracepoints are
// enabled and we can make use of them.
// The argument that is passed to the tracepoint for the sys_enter_read hook is described in sysfs
// at /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format.
SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__sys_enter_read(void *ctx) {
  printt("The read tracepoint was triggered");
  return 0;
}
