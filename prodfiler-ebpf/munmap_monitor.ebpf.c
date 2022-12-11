// This file contains the code for the probe on munmap to report executable memory unmappings.

#include "bpfdefs.h"
#include "tracemgmt.h"

#ifdef TESTING
#include <sys/types.h>  // pid_t
#endif

#include "types.h"

// report_munmap_events represents the communication channel between eBPF and user space to
// notify user space about munmap events.
// As key the CPU number is used and the value represents a perf event file descriptor.
// We use 0 as the number of max entries for this map as at load time it will be replaced
// by the number of possible CPUs. At the same time this will then also define the number
// of perf event rings that are used for this map.
bpf_map_def SEC("maps/report_munmap_events") report_munmap_events = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(u32),
  .max_entries = 0,
};

// munmap_monitor is the communication channel between the entry point of the munmap syscall and the
// exit point. It maps pid/tgid to a memory address.
struct bpf_map_def SEC("maps/munmap_monitor") munmap_monitor = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(u64),
    .max_entries = 8192,
};

// The argument that is passed to the tracepoint for the sys_enter_munmap hook is described in sysfs
// at /sys/kernel/debug/tracing/events/syscalls/sys_enter_munmap/format.
typedef struct munmap_enter_ctx {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;
  int __syscall_nr;
  unsigned long addr;
  size_t len;
} munmap_enter_ctx;

// tracepoint__sys_enter_munmap is a probe attached to the entry point of the munmap syscall.
// Every time a process uses munmap this hook is triggered.
SEC("tracepoint/syscalls/sys_enter_munmap")
int tracepoint__sys_enter_munmap(munmap_enter_ctx *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = (u32)(pid_tgid >> 32);

  // The eBPF verifier requires us to put the passed argument
  // on the stack in order to pass elements of this structure
  // on to bpf_perf_event_output.
  munmap_enter_ctx args;
  int ret = bpf_probe_read(&args, sizeof(args), ctx);
  if (ret < 0) {
    DEBUG_PRINT("failed to read function arguments: error code %d", ret);
    return 0;
  }

  PIDPage key = {};
  key.prefixLen = BIT_WIDTH_PID + BIT_WIDTH_PAGE;
  key.pid = __constant_cpu_to_be32(pid);
  key.page = __constant_cpu_to_be64(args.addr);

  // Check if we have the data for this virtual address
  PIDPageMappingInfo *val = bpf_map_lookup_elem(&pid_page_to_mapping_info, &key);
  if (!val) {
    // Unmapping of a memory mapping we don't track. So don't report it.
    return 0;
  }

  u64 addr = args.addr;
  ret = bpf_map_update_elem(&munmap_monitor, &pid_tgid, &addr, BPF_ANY);
  if (ret) {
    DEBUG_PRINT("update of munmap_monitor failed with error code %d", ret);
  }

  return 0;
}

// The argument that is passed to the tracepoint for the sys_enter_munmap hook is described in sysfs
// at /sys/kernel/debug/tracing/events/syscalls/sys_exit_munmap/format.
typedef struct munmap_exit_ctx {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;
  int __syscall_nr;
  long ret;
} munmap_exit_ctx;

// tracepoint__sys_exit_munmap is a probe attached to the exit point of the munmap syscall. If the
// unmapping was successful and we did track the memory so far, we let user space know about it.
SEC("tracepoint/syscalls/sys_exit_munmap")
int tracepoint__sys_exit_munmap(munmap_exit_ctx *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = (u32)(pid_tgid >> 32);

  u64 *addr = bpf_map_lookup_elem(&munmap_monitor, &pid_tgid);
  if (!addr) {
    // We don't track this unmapping so we can return here.
    return 0;
  }

  // The eBPF verifier requires us to put the passed argument
  // on the stack in order to pass elements of this structure
  // on to bpf_perf_event_output.
  munmap_exit_ctx args;
  int ret = bpf_probe_read(&args, sizeof(args), ctx);
  if (ret < 0) {
    DEBUG_PRINT("failed to read function arguments: error code %d", ret);
    goto exit;
  }

  if (args.ret != 0) {
    // munmap was not successful. So we don't let user space know about it.
    goto exit;
  }

  // Inform the user space part about the unmapping.
  MunmapEvent event = {};
  event.pid = pid;
  event.addr = (u64)*addr;

  increment_metric(metricID_NumMunmapEvent);
  ret = bpf_perf_event_output(ctx, &report_munmap_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  if (ret < 0) {
    DEBUG_PRINT("tracepoint__sys_exit_munmap failed to update report_pid_events: error code %d", ret);
  }

exit:
  ret = bpf_map_delete_elem(&munmap_monitor, &pid_tgid);
  if (ret < 0) {
    DEBUG_PRINT("failed to cleanup %lld from munmap_monitor: error code %d", pid_tgid, ret);
  }

  return 0;
}
