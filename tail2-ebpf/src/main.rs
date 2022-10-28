#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use core::mem::transmute;

use aya_bpf::{
    macros::{uprobe, map, perf_event},
    programs::{ProbeContext, PerfEventContext},
    helpers::{bpf_get_ns_current_pid_tgid, bpf_get_current_task_btf, bpf_task_pt_regs, bpf_probe_read_user_buf},
    maps::{HashMap, PerCpuArray, PerfEventArray, Array, self},
    bindings::{bpf_pidns_info, user_pt_regs, task_struct}, BpfContext
};
use aya_log_ebpf::{error, info};
use tail2_common::{Stack, ConfigMapKey, pidtgid::PidTgid, InfoMapKey, runtime_type::RuntimeType};

#[map(name="STACKS")]
static mut STACKS: PerfEventArray<Stack> = PerfEventArray::new(0);

#[map(name="STACK_BUF")]
static mut STACK_BUF: PerCpuArray<Stack> = PerCpuArray::with_max_entries(1, 0);

#[map(name="CONFIG")]
static CONFIG: HashMap<u32, u64> = HashMap::with_max_entries(10, 0);

#[map(name="RUN_INFO")]
static RUN_INFO: HashMap<u32, u64> = HashMap::with_max_entries(10, 0);

#[map(name="PIDS")]
static PIDS: HashMap<u32, RuntimeType> = HashMap::with_max_entries(1024, 0);

#[uprobe(name="malloc_enter")]
fn malloc_enter(ctx: ProbeContext) -> u32 {
    capture_stack_inner(&ctx)
}

#[perf_event(name="capture_stack")]
fn capture_stack(ctx: PerfEventContext) -> u32 {
    capture_stack_inner(&ctx)
}

fn capture_stack_inner<C: BpfContext>(ctx: &C) -> u32 {
    // let sz = ctx.arg(0).unwrap();

    let dev = unsafe { CONFIG.get(&(ConfigMapKey::DEV as u32)) }.copied().unwrap_or(1);
    let ino = unsafe { CONFIG.get(&(ConfigMapKey::INO as u32)) }.copied().unwrap_or(1);

    let mut ns: bpf_pidns_info = unsafe { core::mem::zeroed() };

    unsafe { bpf_get_ns_current_pid_tgid(dev, ino, &mut ns as *mut bpf_pidns_info, core::mem::size_of::<bpf_pidns_info>() as u32); }

    // try to copy stack
    if let Some(buf_ptr) = unsafe { STACK_BUF.get_ptr_mut(0) } {
        let stack: &mut Stack = unsafe { &mut *buf_ptr };
        stack.pidtgid = PidTgid::current(ns.pid, ns.tgid);

        let task: *mut task_struct = unsafe { bpf_get_current_task_btf() };
        let regs: *const user_pt_regs = unsafe { bpf_task_pt_regs(task) } as *const user_pt_regs;
        stack.sp = unsafe { (*regs).sp };
        stack.pc = unsafe { (*regs).pc };
        stack.lr = unsafe { (*regs).regs[30] };
        stack.fp = unsafe { (*regs).regs[29] };

        let st = stack.sp as *const u8;
        unsafe {
            if let Err(e) = bpf_probe_read_user_buf(st, &mut stack.stuff) {
                error!(ctx, "error when bpf_probe_read_user_buf(): {}", e);
            }
        };

        // #[cfg(debug_assertions)]
        incr_sent_stacks();

        unsafe {
            STACKS.output(ctx, stack, 0);
        }
    }

    0
}

pub fn incr_sent_stacks() {
    let cnt = unsafe { RUN_INFO.get(&(InfoMapKey::SentStackCount as u32)) }.copied().unwrap_or(0);
    unsafe { RUN_INFO.insert(&(InfoMapKey::SentStackCount as u32), &(cnt+1), 0) };
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
