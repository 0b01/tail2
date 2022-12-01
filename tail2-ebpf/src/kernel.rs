use aya_bpf::{BpfContext, bindings::BPF_F_REUSE_STACKID};

use crate::sample::KERNEL_STACKS;

#[inline(always)]
pub fn sample_kernel<C: BpfContext>(ctx: &C) -> i64 {
    /* kernel stack */
    match unsafe { KERNEL_STACKS.get_stackid(ctx, BPF_F_REUSE_STACKID as u64) } {
        Ok(i) => i,
        Err(i) => i,
    }
}
