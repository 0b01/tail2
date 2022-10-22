#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use core::mem::transmute;

use aya_bpf::{
    macros::{uprobe, map},
    programs::ProbeContext,
    helpers::{bpf_get_ns_current_pid_tgid, bpf_get_current_task_btf, bpf_task_pt_regs, bpf_probe_read_user_buf},
    cty::size_t,
    maps::{HashMap, PerCpuArray, PerfEventArray},
    bindings::{bpf_pidns_info, user_pt_regs, task_struct}
};
use aya_log_ebpf::info;
use tail2_common::{Stack, ConfigKey, pidtgid::PidTgid};

#[map(name="STACKS")]
static mut STACKS: PerfEventArray<Stack> = PerfEventArray::new(0);

#[map(name="STACK_BUF")]
static mut STACK_BUF: PerCpuArray<Stack> = PerCpuArray::with_max_entries(1, 0);

#[map(name="CONFIG")]
static CONFIG: HashMap<u32, u64> = HashMap::with_max_entries(10, 0);

#[uprobe(name="malloc_enter")]
pub fn malloc_enter(ctx: ProbeContext) -> u32 {
    let sz: size_t = ctx.arg(0).unwrap();

    info!(&ctx, "malloc: {}", sz);

    let dev = unsafe { CONFIG.get(&(ConfigKey::DEV as u32)) }.copied().unwrap_or(1);
    let ino = unsafe { CONFIG.get(&(ConfigKey::INO as u32)) }.copied().unwrap_or(1);

    let mut ns: bpf_pidns_info = unsafe { core::mem::zeroed() };

    unsafe { bpf_get_ns_current_pid_tgid(dev, ino, &mut ns as *mut bpf_pidns_info, core::mem::size_of::<bpf_pidns_info>() as u32); }

    // try to copy stack
    if let Some(buf_ptr) = unsafe { STACK_BUF.get_ptr_mut(0) } {
        let stack: &mut Stack = unsafe { &mut *buf_ptr };
        stack.pidtgid = PidTgid::current(ns.pid, ns.tgid);

        let task: *mut task_struct = unsafe { bpf_get_current_task_btf() };
        let regs: *const user_pt_regs = unsafe { transmute(bpf_task_pt_regs(task)) };
        stack.sp = unsafe { (*regs).regs[31] };
        stack.pc = unsafe { (*regs).pc };
        stack.lr = unsafe { (*regs).regs[30] };
        stack.fp = unsafe { (*regs).regs[29] };

        let st = stack.sp as *const u8;
        unsafe {
            bpf_probe_read_user_buf(st, &mut stack.stuff).unwrap();
        };

        unsafe {
            STACKS.output(&ctx, stack, 0);
        }
    }

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
