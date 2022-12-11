// Provides functionality for adding frames to traces, hashing traces and
// updating trace counts

#ifndef OPTI_TRACEMGMT_H
#define OPTI_TRACEMGMT_H

#include "bpfdefs.h"
#include "extmaps.h"
#include "frametypes.h"
#include "types.h"

#ifdef TESTING
  #include <errno.h> // EEXIST
#endif

// increment_metric increments the value of the given metricID by 1
static inline __attribute__((__always_inline__))
void increment_metric(u32 metricID) {
  u64 *count = bpf_map_lookup_elem(&metrics, &metricID);
  if (count) {
    ++*count;
  } else {
    DEBUG_PRINT("Failed to lookup metrics map for metricID %d", metricID);
  }
}

// Return the per-cpu record.
// As each per-cpu array only has 1 entry, we hard-code 0 as the key.
// The return value of get_per_cpu_record() can never be NULL and return value checks only exist
// to pass the verifier. If the implementation of get_per_cpu_record() is changed so that NULL can
// be returned, also add an error metric.
static inline PerCPURecord *get_per_cpu_record(void)
{
  int key0 = 0;
  return bpf_map_lookup_elem(&per_cpu_records, &key0);
}

// Return the per-cpu record initialized with pristine values for state variables.
// The return value of get_pristine_per_cpu_record() can never be NULL and return value checks
// only exist to pass the verifier. If the implementation of get_pristine_per_cpu_record() is changed
// so that NULL can be returned, also add an error metric.
static inline PerCPURecord *get_pristine_per_cpu_record()
{
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return record;

  record->state.pc = 0;
  record->state.sp = 0;
  record->state.fp = 0;
  record->state.error_metric = -1;
  record->perlUnwindState.stackinfo = 0;
  record->perlUnwindState.cop = 0;
  record->pythonUnwindState.py_frame = 0;
  record->phpUnwindState.zend_execute_data = 0;
  record->rubyUnwindState.stack_ptr = 0;
  record->rubyUnwindState.last_stack_frame = 0;
  record->ha_symbolization_needed = false;
  record->next_unwinder = PROG_UNWIND_STOP;

  Trace *trace = &record->trace;
  trace->kernel_stack_id = -1;
  trace->stack_len = 0;
  trace->pid = 0;
  trace->python_gil_held = false;
  trace->hash = 0;

  return record;
}

// Push the file ID, line number and frame type into FrameList
static inline __attribute__((__always_inline__))
int _push(Trace *trace, u64 file, u64 line, u8 frame_type) {
#ifdef TESTING_COREDUMP
  // utils/coredump uses CGO to build the eBPF code. This dispatches
  // the frame information directly to helper implemented in ebpfhelpers.go.
  int __push_frame(u64, u64, u64, u8);
  trace->stack_len++;
  return __push_frame(__cgo_ctx->id, file, line, frame_type);
#else
  FrameList *list;
  int framelist_index = trace->stack_len / MAX_FRAME_LIST_SIZE;
  list = bpf_map_lookup_elem(&per_cpu_frame_list, &framelist_index);
  if (!list) {
    DEBUG_PRINT("failed to get frame list");
    return -1;
  }

  u8 list_index = trace->stack_len % MAX_FRAME_LIST_SIZE;
  list->files[list_index] = file;
  list->linenos[list_index] = line;
  list->frame_types[list_index] = frame_type;
  trace->stack_len++;
  return 0;
#endif
}

// Initializer for the generic PID event header
static inline void pid_event_init(PIDEvent *pe, u32 pid, u32 type) {
  pe->pid = pid;
  pe->event_type = type;
}

// Send immediate notifications for event triggers to Go.
// Notifications for UNKNOWN_PC and TRACES_FOR_SYMBOLIZATION will be
// automatically inhibited until HA resets the type.
static inline void pid_event_send_trigger(struct bpf_perf_event_data *ctx, u32 pid, u32 type) {
  int inhibit_key = type;
  bool inhibit_value = true;

  // UNKNOWN_PC and TRACES_FOR_SYMBOLIZATION are global notifications that trigger
  // eBPF map iteration+processing in Go. To avoid redundant notifications while userspace
  // processing for them is already taking place, we allow latch-like inhibition, where Go
  // has to manually reset it.
  if (type == PID_EVENT_TYPE_UNKNOWN_PC || type == PID_EVENT_TYPE_TRACES_FOR_SYMBOLIZATION) {
    if (bpf_map_update_elem(&inhibit_events, &inhibit_key, &inhibit_value, BPF_NOEXIST) < 0) {
      DEBUG_PRINT("pid event type %d inhibited", type);
      return;
    }
  }

  switch (type) {
  case PID_EVENT_TYPE_NEW:
    increment_metric(metricID_NumProcNew);
    break;
  case PID_EVENT_TYPE_EXIT:
    increment_metric(metricID_NumProcExit);
    break;
  case PID_EVENT_TYPE_UNKNOWN_PC:
    increment_metric(metricID_NumUnknownPC);
    break;
  case PID_EVENT_TYPE_TRACES_FOR_SYMBOLIZATION:
    increment_metric(metricID_NumSymbolizeTrace);
    break;
  default:
    // no action
    break;
  }

  PIDEvent event = {};
  pid_event_init(&event, pid, type);
  int ret = bpf_perf_event_output(ctx, &report_pid_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  if (ret < 0) {
    DEBUG_PRINT("pid_event_send_trigger failed to send PID event %d: error %d", type, ret);
  }
}

// 32- and 64-bit finalizer functions for Murmur3_32
// 32-bit via https://en.wikipedia.org/wiki/MurmurHash#Algorithm
// 64-bit via https://lemire.me/blog/2018/08/15/fast-strongly-universal-64-bit-hashing-everywhere/
static inline __attribute__((__always_inline__))
u32 hash32(u32 x) {
  x ^= x >> 16;
  x *= 0x85ebca6b;
  x ^= x >> 13;
  x *= 0xc2b2ae35;
  x ^= x >> 16;
  return x;
}

static inline __attribute__((__always_inline__))
u64 hash64(u64 x) {
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdL;
  x ^= x >> 33;
  x *= 0xc4ceb9fe1a85ec53L;
  x ^= x >> 33;
  return x;
}

// Forward declaration
struct bpf_perf_event_data;

// pid_information_exists checks if the given pid exists in pid_page_to_mapping_info or not.
static inline __attribute__((__always_inline__))
bool pid_information_exists(void *ctx, int pid) {
  PIDPage key = {};
  key.prefixLen = BIT_WIDTH_PID + BIT_WIDTH_PAGE;
  key.pid = __constant_cpu_to_be32((u32) pid);
  key.page = 0;

  return bpf_map_lookup_elem(&pid_page_to_mapping_info, &key) != NULL;
}

// report_new_pid informs user space about a new process.
static inline __attribute__((__always_inline__))
void report_new_pid(void *ctx, int pid) {
  u32 key = (u32) pid;
  u64 ts = bpf_ktime_get_ns();

  int errNo = bpf_map_update_elem(&reported_pids, &key, &ts, BPF_NOEXIST);
  switch (errNo){
    case -EEXIST:
      DEBUG_PRINT("Process %d was recently reported. User space will not be notified", pid);
      return;
    case 0:
      // A new pid was written to reported_pids. Continue here to report the pid also to user space.
      break;
    default:
      DEBUG_PRINT("Failed to report new process %d: %d", pid, errNo);
      increment_metric(metricID_ReportedPIDsErr);
      return;
  }

  pid_event_send_trigger(ctx, pid, PID_EVENT_TYPE_NEW);
}

// is_kernel_address checks if the given address looks like virtual address to kernel memory.
static bool is_kernel_address(u64 addr) {
  return addr & 0xFF00000000000000UL;
}

// resolve_unwind_mapping decodes the current PC's mapping and prepares unwinding information.
// The state text_section_id and text_section_offset are updated accordingly. The return value
// is the unwinding program index that should be used.
static int resolve_unwind_mapping(PerCPURecord *record) {
  UnwindState *state = &record->state;
  pid_t pid = record->trace.pid;
  u64 pc = state->pc;

  if (is_kernel_address(pc)) {
    // This should not happen as we should only be unwinding usermode stacks.
    // Seeing PC point to a kernel address indicates a bad unwind.
    DEBUG_PRINT("PC value %lx is a kernel address", (unsigned long) pc);
    state->error_metric = metricID_UnwindNativeErrKernelAddress;
    return PROG_UNWIND_STOP;
  }

  if (pc < 0x1000) {
    // The kernel will always return a start address for user space memory mappings that is
    // above the value defined in /proc/sys/vm/mmap_min_addr.
    // As such small PC values happens regularly (e.g. by handling or extracting the
    // PC value incorrectly) we track them but don't proceed with unwinding.
    DEBUG_PRINT("small pc value %lx, ignoring", (unsigned long) pc);
    state->error_metric = metricID_UnwindNativeSmallPC;
    return PROG_UNWIND_STOP;
  }

  PIDPage key = {};
  key.prefixLen = BIT_WIDTH_PID + BIT_WIDTH_PAGE;
  key.pid = __constant_cpu_to_be32((u32) pid);
  key.page = __constant_cpu_to_be64(pc);

  // Check if we have the data for this virtual address
  PIDPageMappingInfo* val = bpf_map_lookup_elem(&pid_page_to_mapping_info, &key);
  if (!val) {
    DEBUG_PRINT("Failure to look up interval memory mapping for PC 0x%lx",
                (unsigned long) pc);
    state->error_metric = metricID_UnwindNativeErrWrongTextSection;
    return PROG_UNWIND_STOP;
  }

  int unwind_program;
  decode_bias_and_unwind_program(val->bias_and_unwind_program, &state->text_section_bias, &unwind_program);
  state->text_section_id = val->file_id;
  state->text_section_offset = pc - state->text_section_bias;
  DEBUG_PRINT("Text section id for PC %lx is %llx (unwinder %d)",
    (unsigned long) pc, state->text_section_id, unwind_program);
  return unwind_program;
}

// get_next_interpreter tries to get the next interpreter unwinder from the section id.
// If the section id happens to be within the range of a known interpreter it will
// return the interpreter unwinder otherwise the native unwinder.
static inline int get_next_interpreter(UnwindState *state) {
  u64 section_id = state->text_section_id;
  u64 section_offset = state->text_section_offset;
  // Check if the section id happens to be in the interpreter map.
  OffsetRange *range = bpf_map_lookup_elem(&interpreter_offsets, &section_id);
  if (range != 0) {
    if ((section_offset >= range->lower_offset) && (section_offset <= range->upper_offset)) {
      DEBUG_PRINT("interpreter_offsets match %d", range->program_index);
      increment_metric(metricID_UnwindCallInterpreter);
      return range->program_index;
    }
  }
  return PROG_UNWIND_NATIVE;
}

// get_next_unwinder determines the next unwinder program to run. If resolve_pc is set,
// the memory mapping for current PC is looked up and prepared for unwinding. It is usually
// set false only when an interpreter unwinder was called via interpreter_offsets hook, so
// the native unwinding can continue where it left off.
static inline __attribute__((__always_inline__))
int get_next_unwinder(PerCPURecord *record) {
  UnwindState *state = &record->state;
  if (state->pc == 0) {
    DEBUG_PRINT("Stopping unwind due to unwind failure (PC == 0)");
    state->error_metric = metricID_UnwindErrZeroPC;
    return PROG_UNWIND_STOP;
  }

  // The limit is MAX_FRAME_UNWINDS.
  if (record->trace.stack_len >= MAX_FRAME_UNWINDS) {
    DEBUG_PRINT("Stopping unwind as stack length %d >= %d",
                record->trace.stack_len, MAX_FRAME_UNWINDS);
    state->error_metric = metricID_UnwindErrStackLengthExceeded;
    return PROG_UNWIND_STOP;
  }

  DEBUG_PRINT("==== Resolve next frame unwinder: frame %d ====", record->trace.stack_len);
  int unwinder = resolve_unwind_mapping(record);
  if (unwinder == PROG_UNWIND_NATIVE) {
    record->next_unwinder = PROG_UNWIND_NATIVE;
    unwinder = get_next_interpreter(state);
  }
  return unwinder;
}

#endif
