use aya_bpf::{helpers::bpf_ktime_get_ns, BpfContext};
use tail2_common::{metrics::Metrics, tracemgmt::PidEvent};

const EEXIST: i64 = 17;

use crate::maps::{PID_EVENT, PIDS, PID_REPORTS};

pub fn pid_info_exists(pid: u32) -> bool {
    unsafe { PIDS.get(&pid) }.is_some()
}

pub fn report_new_pid<C: BpfContext>(ctx: &C, pid: u32) -> Result<(), Metrics> {
    let ts = unsafe { bpf_ktime_get_ns() };
    if unsafe { PID_REPORTS.get(&pid) }.is_some() {
        return Err(Metrics::TraceMgmt_NewPidAlreadyNotified);
    }

    match unsafe { PID_REPORTS.insert(&pid, &ts, 0) } {
        Ok(()) => {
            report_pid_event(ctx, pid, Metrics::TraceMgmt_NewPid);
            Err(Metrics::TraceMgmt_NewPid)
        }
        Err(e) => {
            Err(Metrics::TraceMgmt_PidErr)
        }
    }
}

fn report_pid_event<C: BpfContext>(ctx: &C, pid: u32, metrics: Metrics) {
    let data = PidEvent {
        pid,
        event_type: metrics,
    };
    unsafe { PID_EVENT.output(ctx, &data, 0) };
}