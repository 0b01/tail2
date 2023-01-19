use aya_bpf::{helpers::{bpf_probe_read_user, bpf_get_current_task, bpf_task_pt_regs, bpf_get_current_task_btf}, BpfContext, bindings::bpf_pidns_info};
use aya_log_ebpf::{error, info};
use tail2_common::{NativeStack, ConfigMapKey, pidtgid::PidTgid, procinfo::{ProcInfo, MAX_ROWS_PER_PROC}, native::unwinding::{aarch64::{unwind_rule::UnwindRuleAarch64, unwindregs::UnwindRegsAarch64}, x86_64::unwind_rule::UnwindRuleX86_64}, MAX_USER_STACK, bpf_sample::BpfSample, native::unwinding::x86_64::unwindregs::UnwindRegsX86_64, metrics::Metrics};
use aya_bpf::bindings::pt_regs;

use crate::{vmlinux::task_struct, helpers::get_pid_tgid};
use crate::sample::PIDS;

#[cfg(feature = "x86_64")]
type UnwindRegs = UnwindRegsX86_64;
#[cfg(feature = "aarch64")]
type UnwindRegs = UnwindRegsAarch64;

#[cfg(feature = "x86_64")]
type UnwindRule = UnwindRuleX86_64;
#[cfg(feature = "aarch64")]
type UnwindRule = UnwindRuleAarch64;


pub(crate) fn sample_user<'a, 'b, C: BpfContext>(ctx: &'a C, st: &mut NativeStack, pid: u32) -> Result<(), Metrics> {
    /* unwind user stack */
    let task = unsafe { bpf_get_current_task_btf()};
    let regs = unsafe { bpf_task_pt_regs(task) } as *const _;
    // let regs = ctx.as_ptr() as *const _;
    let pc = get_pc(regs);
    let mut regs = get_regs(regs);
    unwind(ctx, st, pc, &mut regs, pid);

    Ok(())
}

fn unwind<C: BpfContext>(
    ctx: &C,
    st: &mut NativeStack,
    pc: usize,
    regs: &mut UnwindRegs,
    pid: u32
) -> Result<(), Metrics> {
    let proc_info = unsafe { PIDS.get(&pid).ok_or(Metrics::ErrSample_NoPidInfo)? };

    let mut read_stack = |addr: u64| {
        let ret = unsafe { bpf_probe_read_user(addr as *const u64) };
        // info!(ctx, "read_stack: {}, result: {}", addr, ret.unwrap_err());
        ret.map_err(|_|())
    };

    let mut frame = pc;
    let mut is_first_frame = true;
    st.native_stack[0] = pc;
    for i in 1..MAX_USER_STACK {
        let idx = binary_search(proc_info.rows.as_slice(), frame, proc_info.rows_len)?;
        let rule = proc_info.rows[idx].1;
        // info!(ctx, "rule: {}", rule.as_num());

        match rule.exec(is_first_frame, regs, &mut read_stack) {
            Ok(Some(f)) => {
                st.native_stack[i] = f as usize;
                frame = f as usize;
            }
            Ok(None) => {
                st.unwind_success = Some(i);
                break;
            },
            Err(e) => {
                // error!(ctx, "error unwinding");
                st.unwind_success = None;
                return Err(e.into());
            }
        }
        is_first_frame = false;
    }

    Ok(())
}

#[inline(always)]
/// binary search routine that passes the bpf verifier
fn binary_search(rows: &[(usize, UnwindRule)], pc: usize, right: usize) -> Result<usize, Metrics> {
    let mut left = 0;
    let mut right = right;
    let mut found = 0;
    for _ in 0..20 {
        if left >= right {
          return Ok(found);
        }
      
        let mid = (left + right) / 2;

        // appease the verifier
        if mid >= MAX_ROWS_PER_PROC {
            return Err(Metrics::ErrSample_BinarySearch);
        }

        if rows[mid].0 <= pc {
          found = mid;
          left = mid + 1;
        } else {
          right = mid;
        }
    }

    Err(Metrics::ErrSample_BinarySearch)
}

#[cfg(feature = "x86_64")]
fn get_pc(regs: *const pt_regs) -> usize {
    unsafe { (*regs).rip as usize }
}
#[cfg(feature = "aarch64")]
fn get_pc(regs: *const aya_bpf::bindings::user_pt_regs) -> usize {
    unsafe { (*regs).pc as usize }
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