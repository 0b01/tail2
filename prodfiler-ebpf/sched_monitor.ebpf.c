// This file contains the code and map definitions for the tracepoint on the scheduler to
// report the stopping a process.

#include "bpfdefs.h"
#include "tracemgmt.h"

#ifdef TESTING
  #include <sys/types.h> // pid_t
#endif

#include "types.h"

// tracepoint__sched_process_exit is a tracepoint attached to the scheduler that stops processes.
// Every time a processes stops this hook is triggered.
SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched_process_exit(void *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = (u32)(pid_tgid >> 32);
  u32 tid = (u32)(pid_tgid & 0xFFFFFFFF);

  if (pid != tid) {
    // Only if the thread group ID matched with the PID the process itself exits. If they don't
    // match only a thread of the process stopped and we do not need to report this PID to
    // userspace for further processing.
    return 0;
  }

  // At this point we don't check if the deletion of PID from reported_pids was successful or not,
  // as the removal of elements from this map can happen also in other places. So to avoid
  // spamming our debug output nothing is logged at this point.
  bpf_map_delete_elem(&reported_pids, &pid);

  pid_event_send_trigger(ctx, pid, PID_EVENT_TYPE_EXIT);
  return 0;
}
