use aya_bpf::{macros::map, maps::{PerfEventArray, PerCpuArray, HashMap, StackTrace}};
use tail2_common::{bpf_sample::BpfSample, procinfo::ProcInfo, metrics::Metrics, tracemgmt::PidEvent};

/// Used to send samples to user space
#[map(name="STACKS")]
pub(crate) static mut STACKS: PerfEventArray<BpfSample> = PerfEventArray::new(0);

/// Used to send pid events to user space
#[map(name="PID_EVENT")]
pub(crate) static mut PID_EVENT: PerfEventArray<PidEvent> = PerfEventArray::new(0);

/// Used as a heap
#[map(name="STACK_BUF")]
pub(crate) static mut STACK_BUF: PerCpuArray<BpfSample> = PerCpuArray::with_max_entries(1, 0);

/// Used to store misc config
#[map(name="CONFIG")]
pub(crate) static CONFIG: HashMap<u32, u64> = HashMap::with_max_entries(10, 0);

/// Used to store kernel stacks
#[map(name="KERNEL_STACKS")]
pub(crate) static KERNEL_STACKS: StackTrace = StackTrace::with_max_entries(10, 0);

/// PID unwind information
#[map(name="PIDS")]
pub(crate) static PIDS: HashMap<u32, ProcInfo> = HashMap::with_max_entries(512, 0);

/// A map of pid -> timestamp of when we recently triggered it
#[map(name="PID_REPORTS")]
pub(crate) static PID_REPORTS: HashMap<u32, u64> = HashMap::with_max_entries(512, 0);

/// metrics -> count
#[map(name="METRICS")]
pub(crate) static METRICS: HashMap<u32, u64> = HashMap::with_max_entries(Metrics::Max as u32, 0);
