use aya_bpf::{
    macros::{uprobe, map, perf_event},
    programs::{ProbeContext, PerfEventContext},
    helpers::{bpf_get_ns_current_pid_tgid, bpf_get_current_task_btf, bpf_task_pt_regs, bpf_probe_read_user, bpf_get_current_task},
    maps::{HashMap, PerCpuArray, PerfEventArray, StackTrace},
    bindings::{bpf_pidns_info, pt_regs, BPF_F_REUSE_STACKID}, BpfContext
};
use tail2_common::{bpf_sample::BpfSample, procinfo::ProcInfo, native::unwinding::{aarch64::{unwind_rule::UnwindRuleAarch64, unwindregs::UnwindRegsAarch64}, x86_64::unwindregs::UnwindRegsX86_64}, RunStatsKey, NativeStack, python::state::PythonStack, pidtgid::PidTgid};
use aya_log_ebpf::{error, info};

use crate::{pyperf::pyperf::sample_python, user::sample_user, helpers::get_pid_tgid};

#[map(name="STACKS")]
pub(crate) static mut STACKS: PerfEventArray<BpfSample> = PerfEventArray::new(0);

#[map(name="STACK_BUF")]
pub(crate) static mut STACK_BUF: PerCpuArray<BpfSample> = PerCpuArray::with_max_entries(1, 0);

#[map(name="CONFIG")]
pub(crate) static CONFIG: HashMap<u32, u64> = HashMap::with_max_entries(10, 0);

#[map(name="RUN_STATS")]
pub(crate) static RUN_STATS: HashMap<u32, u64> = HashMap::with_max_entries(10, 0);

#[map(name="KERNEL_STACKS")]
pub(crate) static KERNEL_STACKS: StackTrace = StackTrace::with_max_entries(10, 0);

#[map(name="PIDS")]
pub(crate) static PIDS: HashMap<u32, ProcInfo> = HashMap::with_max_entries(512, 0);

#[uprobe(name="malloc_enter")]
fn malloc_enter(ctx: ProbeContext) -> Option<u32> {
    // let sz = ctx.arg(0).unwrap();

    let st: &mut BpfSample = unsafe { &mut *(STACK_BUF.get_ptr_mut(0)?) };
    st.clear();

    let ns: bpf_pidns_info = get_pid_tgid();
    st.pidtgid = PidTgid::current(ns.pid, ns.tgid);

    st.native_stack = Some(NativeStack::uninit());
    sample_user(&ctx, st.native_stack.as_mut().unwrap(), ns.pid);

    st.kernel_stack_id = sample_kernel(&ctx);

    unsafe {
        STACKS.output(&ctx, st, 0);
        incr_sent_stacks();
    }

    Some(0)
}

#[perf_event(name="capture_stack")]
fn capture_stack(ctx: PerfEventContext) -> Option<u32> {
    let st: &mut BpfSample = unsafe { &mut *(STACK_BUF.get_ptr_mut(0)?) };
    st.clear();

    let ns: bpf_pidns_info = get_pid_tgid();
    st.pidtgid = PidTgid::current(ns.pid, ns.tgid);

    st.native_stack = Some(NativeStack::uninit());
    sample_user(&ctx, st.native_stack.as_mut().unwrap(), ns.pid);

    st.kernel_stack_id = sample_kernel(&ctx);

    unsafe {
        STACKS.output(&ctx, st, 0);
        incr_sent_stacks();
    }
    Some(0)
}

#[perf_event(name="pyperf")]
fn pyperf(ctx: PerfEventContext) -> Option<u32> {
    let st: &mut BpfSample = unsafe { &mut *(STACK_BUF.get_ptr_mut(0)?) };
    st.clear();

    let ns: bpf_pidns_info = get_pid_tgid();
    st.pidtgid = PidTgid::current(ns.pid, ns.tgid);

    st.native_stack = Some(NativeStack::uninit());
    sample_user(&ctx, st.native_stack.as_mut().unwrap(), ns.pid);

    st.python_stack = Some(PythonStack::uninit());
    let result = sample_python(&ctx, st.python_stack.as_mut().unwrap());

    st.kernel_stack_id = sample_kernel(&ctx);

    // match result {
    //     Ok(v) => info!(&ctx, "ok: {}", v as usize),
    //     Err(e) => (), //info!(&ctx, "err: {}", e as usize),
    // }

    unsafe {
        STACKS.output(&ctx, st, 0);
        incr_sent_stacks();
    }

    Some(0)
}


fn sample_kernel<C: BpfContext>(ctx: &C) -> i64 {
    /* kernel stack */
    match unsafe { KERNEL_STACKS.get_stackid(ctx, BPF_F_REUSE_STACKID as u64) } {
        Ok(i) => i,
        Err(i) => i,
    }
}

pub fn incr_sent_stacks() {
    let cnt = unsafe { RUN_STATS.get(&(RunStatsKey::SentStackCount as u32)) }.copied().unwrap_or(0);
    let _ = RUN_STATS.insert(&(RunStatsKey::SentStackCount as u32), &(cnt+1), 0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}