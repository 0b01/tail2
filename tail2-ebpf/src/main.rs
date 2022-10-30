#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

mod unwinding;

use core::mem::transmute;

use aya_bpf::{
    macros::{uprobe, map, perf_event},
    programs::{ProbeContext, PerfEventContext},
    helpers::{bpf_get_ns_current_pid_tgid, bpf_get_current_task_btf, bpf_task_pt_regs, bpf_probe_read_user_buf},
    maps::{HashMap, PerCpuArray, PerfEventArray, Array, self},
    bindings::{bpf_pidns_info, user_pt_regs, task_struct}, BpfContext
};
use aya_log_ebpf::{error, info};
use tail2_common::{Stack, ConfigMapKey, pidtgid::PidTgid, InfoMapKey, runtime_type::RuntimeType, stack::{USER_STACK_PAGES, PAGE_SIZE}, procinfo::ProcInfo, module::Module};

#[map(name="STACKS")]
static mut STACKS: PerfEventArray<Stack> = PerfEventArray::new(0);

#[map(name="STACK_BUF")]
static mut STACK_BUF: PerCpuArray<Stack> = PerCpuArray::with_max_entries(1, 0);

#[map(name="CONFIG")]
static CONFIG: HashMap<u32, u64> = HashMap::with_max_entries(10, 0);

#[map(name="RUN_INFO")]
static RUN_INFO: HashMap<u32, u64> = HashMap::with_max_entries(10, 0);

#[map(name="MODS")]
static MODS: HashMap<u32, Module> = HashMap::with_max_entries(512, 0);

#[map(name="PIDS")]
static PIDS: HashMap<u32, ProcInfo> = HashMap::with_max_entries(1024, 0);

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
        let st: &mut Stack = unsafe { &mut *buf_ptr };
        st.pidtgid = PidTgid::current(ns.pid, ns.tgid);

        let task: *mut task_struct = unsafe { bpf_get_current_task_btf() };
        let regs: *const user_pt_regs = unsafe { bpf_task_pt_regs(task) } as *const user_pt_regs;
        st.sp = unsafe { (*regs).sp };
        st.pc = unsafe { (*regs).pc };
        st.lr = unsafe { (*regs).regs[30] };
        st.fp = unsafe { (*regs).regs[29] };

        let st_ptr = st.sp as *const u8;
        for i in 0..USER_STACK_PAGES {
            if let Err(e) = unsafe { bpf_probe_read_user_buf(st_ptr, &mut st.raw_user_stack[i * PAGE_SIZE..(i+1) * PAGE_SIZE]) } {
                error!(ctx, "error when bpf_probe_read_user_buf(): {}", e);
                break;
            }
            st.user_stack_len = (i + 1) * PAGE_SIZE;
        }

        // #[cfg(debug_assertions)]
        incr_sent_stacks();

        unsafe {
            STACKS.output(ctx, st, 0);
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
