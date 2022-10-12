#![no_std]
#![no_main]

use aya_bpf::{
    macros::{uprobe, map},
    programs::ProbeContext, helpers::{bpf_get_current_pid_tgid, bpf_get_ns_current_pid_tgid}, cty::size_t, maps::{StackTrace, Queue, HashMap}, bindings::{BPF_F_USER_STACK, bpf_pidns_info}
};
use aya_log_ebpf::info;
use tail2_common::ConfigKey;

#[map(name="STACK_TRACES")]
static STACK_TRACES: StackTrace = StackTrace::with_max_entries(10, 0);

#[map(name="STACKS")]
static STACKS_Q: Queue<[u32; 3]> = Queue::with_max_entries(1024, 0);

#[map(name="CONFIG")]
static CONFIG: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[uprobe(name="malloc_enter")]
pub fn malloc_enter(ctx: ProbeContext) -> u32 {
    let sz: size_t = ctx.arg(0).unwrap();

    let dev = unsafe { CONFIG.get(&(ConfigKey::DEV as u32)) }.copied().unwrap_or(1);
    let ino = unsafe { CONFIG.get(&(ConfigKey::INO as u32)) }.copied().unwrap_or(1);

    let mut ns: bpf_pidns_info = bpf_pidns_info {
        pid: 1,
        tgid: 1,
    };

    unsafe { bpf_get_ns_current_pid_tgid(dev, ino, &mut ns as *mut bpf_pidns_info, core::mem::size_of::<bpf_pidns_info>() as u32); }

    let ustack = unsafe { STACK_TRACES.get_stackid(&ctx, BPF_F_USER_STACK as _) };

    match ustack {
        Ok(ustack) => {
            // info!(&ctx, "pushing");
            if let Err(e) = STACKS_Q.push(&[ns.pid, ustack as u32, sz as u32], 0) {
                info!(&ctx, "Error pushing stack: {}", e);
            }
        },
        _ => {}
    }

    // info!(&ctx, "malloc: {}", sz);
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
