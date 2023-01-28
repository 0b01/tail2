use aya_bpf::{
    macros::{uprobe, map, perf_event},
    programs::{ProbeContext, PerfEventContext},
    helpers::{bpf_get_ns_current_pid_tgid, bpf_get_current_task_btf, bpf_task_pt_regs, bpf_probe_read_user, bpf_get_current_task, bpf_ktime_get_ns},
    maps::{HashMap, PerCpuArray, PerfEventArray, StackTrace},
    bindings::{bpf_pidns_info, pt_regs, BPF_F_REUSE_STACKID}, BpfContext
};
use tail2_common::{bpf_sample::BpfSample, procinfo::ProcInfo, native::unwinding::{aarch64::{unwind_rule::UnwindRuleAarch64, unwindregs::UnwindRegsAarch64}, x86_64::unwindregs::UnwindRegsX86_64}, NativeStack, python::state::PythonStack, pidtgid::PidTgid, metrics::Metrics};
use aya_log_ebpf::{error, info};

use crate::{pyperf::pyperf::sample_python, user::sample_user, helpers::get_pid_tgid, kernel::sample_kernel};

#[map(name="STACKS")]
pub(crate) static mut STACKS: PerfEventArray<BpfSample> = PerfEventArray::new(0);

#[map(name="STACK_BUF")]
pub(crate) static mut STACK_BUF: PerCpuArray<BpfSample> = PerCpuArray::with_max_entries(1, 0);

#[map(name="CONFIG")]
pub(crate) static CONFIG: HashMap<u32, u64> = HashMap::with_max_entries(10, 0);

#[map(name="KERNEL_STACKS")]
pub(crate) static KERNEL_STACKS: StackTrace = StackTrace::with_max_entries(10, 0);

#[map(name="PIDS")]
pub(crate) static PIDS: HashMap<u32, ProcInfo> = HashMap::with_max_entries(512, 0);

#[map(name="METRICS")]
pub(crate) static METRICS: HashMap<u32, u64> = HashMap::with_max_entries(Metrics::Max as u32, 0);

#[uprobe(name="malloc_enter_0")] fn malloc_enter_0(ctx: ProbeContext) { /* let sz = ctx.arg(0).unwrap(); */ sample(&ctx, 0); }
#[uprobe(name="malloc_enter_1")] fn malloc_enter_1(ctx: ProbeContext) { /* let sz = ctx.arg(0).unwrap(); */ sample(&ctx, 1); }
#[uprobe(name="malloc_enter_2")] fn malloc_enter_2(ctx: ProbeContext) { /* let sz = ctx.arg(0).unwrap(); */ sample(&ctx, 2); }
#[uprobe(name="malloc_enter_3")] fn malloc_enter_3(ctx: ProbeContext) { /* let sz = ctx.arg(0).unwrap(); */ sample(&ctx, 3); }
#[uprobe(name="malloc_enter_4")] fn malloc_enter_4(ctx: ProbeContext) { /* let sz = ctx.arg(0).unwrap(); */ sample(&ctx, 4); }

#[perf_event(name="capture_stack_0")] fn capture_stack_0(ctx: PerfEventContext) { sample(&ctx, 0); }
#[perf_event(name="capture_stack_1")] fn capture_stack_1(ctx: PerfEventContext) { sample(&ctx, 1); }
#[perf_event(name="capture_stack_2")] fn capture_stack_2(ctx: PerfEventContext) { sample(&ctx, 2); }
#[perf_event(name="capture_stack_3")] fn capture_stack_3(ctx: PerfEventContext) { sample(&ctx, 3); }
#[perf_event(name="capture_stack_4")] fn capture_stack_4(ctx: PerfEventContext) { sample(&ctx, 4); }

fn sample<C: BpfContext>(ctx: &C, idx: usize) {
    if let Err(e) = sample_inner(ctx, idx) {
        incr_metric(e);
    }
}

fn sample_inner<C: BpfContext>(ctx: &C, idx: usize) -> Result<(), Metrics> {
    let sample = unsafe { &mut *(STACK_BUF.get_ptr_mut(0).ok_or(Metrics::ErrSample_CantAlloc)?) };
    let ns: bpf_pidns_info = get_pid_tgid();
    sample.pidtgid = PidTgid::current(ns.pid, ns.tgid);
    sample.ts = unsafe { bpf_ktime_get_ns() };
    sample.idx = idx;

    sample.native_stack = NativeStack::uninit();
    sample_user(ctx, &mut sample.native_stack, ns.pid)?;

    sample.python_stack = Some(PythonStack::uninit());
    let stack = sample.python_stack.as_mut().ok_or(Metrics::ErrPy_NoStack)?;
    let result = sample_python(ctx, stack);
    if let Err(e) = result {
        incr_metric(e);
    }

    sample.kernel_stack_id = sample_kernel(ctx);

    unsafe {
        STACKS.output(ctx, sample, 0);
        incr_metric(Metrics::SentStackCount);
    }

    Ok(())
}

pub fn incr_metric(key: Metrics) {
    let cnt = unsafe { METRICS.get(&(key as u32)) }.copied().unwrap_or(0);
    let _ = METRICS.insert(&(key as u32), &(cnt+1), 0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}