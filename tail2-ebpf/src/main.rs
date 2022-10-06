#![no_std]
#![no_main]

use aya_bpf::{
    macros::uprobe,
    programs::ProbeContext, helpers::{bpf_probe_read, bpf_probe_read_user_str_bytes}, cty::size_t
};
use aya_log_ebpf::info;

#[uprobe(name="malloc_enter")]
pub fn malloc_enter(ctx: ProbeContext) -> u32 {
    let sz: size_t = ctx.arg(0).unwrap();
    info!(&ctx, "malloc: {}", sz);
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
