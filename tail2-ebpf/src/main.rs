#![no_std]
#![no_main]
#![allow(unused, nonstandard_style, dead_code)]

use aya_bpf::{
    macros::{uprobe, map, perf_event},
    programs::{ProbeContext, PerfEventContext},
    helpers::{bpf_get_ns_current_pid_tgid, bpf_get_current_task_btf, bpf_task_pt_regs, bpf_probe_read_user},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    bindings::{bpf_pidns_info, pt_regs, task_struct}, BpfContext
};
use aya_log_ebpf::{error, info};
use tail2_common::{Stack, ConfigMapKey, pidtgid::PidTgid, InfoMapKey, procinfo::{ProcInfo, MAX_ROWS_PER_PROC}, unwinding::{aarch64::{unwind_rule::UnwindRuleAarch64, unwindregs::UnwindRegsAarch64}, x86_64::unwind_rule::UnwindRuleX86_64}, MAX_USER_STACK};
use tail2_common::unwinding::x86_64::unwindregs::UnwindRegsX86_64;

#[cfg(feature = "x86_64")]
type UnwindRegs = UnwindRegsX86_64;
#[cfg(feature = "aarch64")]
type UnwindRegs = UnwindRegsAarch64;

#[cfg(feature = "x86_64")]
type UnwindRule = UnwindRuleX86_64;
#[cfg(feature = "aarch64")]
type UnwindRule = UnwindRuleAarch64;

#[map(name="STACKS")]
static mut STACKS: PerfEventArray<Stack> = PerfEventArray::new(0);

#[map(name="STACK_BUF")]
static mut STACK_BUF: PerCpuArray<Stack> = PerCpuArray::with_max_entries(1, 0);

#[map(name="CONFIG")]
static CONFIG: HashMap<u32, u64> = HashMap::with_max_entries(10, 0);

/// See InfoMapKey
#[map(name="RUN_INFO")]
static RUN_INFO: HashMap<u32, u64> = HashMap::with_max_entries(10, 0);

#[map(name="PIDS")]
static PIDS: HashMap<u32, ProcInfo> = HashMap::with_max_entries(256, 0);

#[uprobe(name="malloc_enter")]
fn malloc_enter(ctx: ProbeContext) -> u32 {
    capture_stack_inner(&ctx)
}

#[perf_event(name="capture_stack")]
fn capture_stack(ctx: PerfEventContext) -> u32 {
    capture_stack_inner(&ctx)
}

fn capture_stack_inner<C: BpfContext>(ctx: &C) -> u32 {
    info!(ctx, "test");
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
        let regs = unsafe { bpf_task_pt_regs(task) } as *const _;

        let pc = get_pc(regs);
        let mut regs = get_regs(regs); {
        };

        unwind(ctx, st, pc, &mut regs);

        incr_sent_stacks();

        unsafe {
            STACKS.output(ctx, st, 0);
        }
    }

    0
}

fn unwind<C: BpfContext>(ctx: &C, st: &mut Stack, pc: u64, regs: &mut UnwindRegs) -> Option<()> {
    let proc_info = unsafe { PIDS.get(&st.pid())? };

    let mut read_stack = |addr: u64| {
        unsafe { bpf_probe_read_user(addr as *const u64).map_err(|_|()) }
    };

    let mut frame = pc;
    let mut is_first_frame = true;
    st.user_stack[0] = pc;
    for i in 1..MAX_USER_STACK {
        let idx = binary_search(proc_info.rows.as_slice(), frame, proc_info.rows_len)?;
        let rule = proc_info.rows[idx].1;

        match rule.exec(is_first_frame, regs, &mut read_stack) {
            Some(Some(f)) => {
                st.user_stack[i] = f;
                frame = f;
            }
            Some(None) => {
                st.unwind_success = Some(i);
                break;
            },
            None => {
                error!(ctx, "error unwinding");
                st.unwind_success = None;
                break;
            }
        }
        is_first_frame = false;
    }

    Some(())
}

/// binary search routine that passes the bpf verifier
fn binary_search(rows: &[(u64, UnwindRule)], pc: u64, right: usize) -> Option<usize> {
    let mut left = 0;
    let mut right = right;
    let mut found = 0;
    for _ in 0..20 {
        if left >= right {
          return Some(found);
        }
      
        let mid = (left + right) / 2;

        // appease the verifier
        if mid >= MAX_ROWS_PER_PROC {
          return None;
        }

        if rows[mid].0 <= pc {
          found = mid;
          left = mid + 1;
        } else {
          right = mid;
        }
    }

    None
}

pub fn incr_sent_stacks() {
    let cnt = unsafe { RUN_INFO.get(&(InfoMapKey::SentStackCount as u32)) }.copied().unwrap_or(0);
    let _ = RUN_INFO.insert(&(InfoMapKey::SentStackCount as u32), &(cnt+1), 0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(feature = "x86_64")]
fn get_pc(regs: *const pt_regs) -> u64 {
    unsafe { (*regs).rip }
}
#[cfg(feature = "aarch64")]
fn get_pc(regs: *const aya_bpf::bindings::user_pt_regs) -> u64 {
    unsafe { (*regs).pc }
}
#[cfg(feature = "aarch64")]
fn get_regs(regs: *const aya_bpf::bindings::user_pt_regs) -> UnwindRegsAarch64 {
    UnwindRegsAarch64::new(
        unsafe { (*regs).regs[30] },
        unsafe { (*regs).sp },
        unsafe { (*regs).regs[29] })
}
#[cfg(feature = "x86_64")]
fn get_regs(regs: *const pt_regs) -> UnwindRegsX86_64 {
    UnwindRegsX86_64::new(
        unsafe { (*regs).rip },
        unsafe { (*regs).rsp },
        unsafe { (*regs).rbp })
}
