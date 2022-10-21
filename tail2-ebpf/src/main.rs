#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use core::{mem::{transmute, self}, char::MAX};

use aya_bpf::{
    macros::{uprobe, map},
    programs::ProbeContext, helpers::{bpf_get_ns_current_pid_tgid, bpf_get_current_task_btf, bpf_task_pt_regs, gen, bpf_map_lookup_elem, bpf_map_update_elem, bpf_probe_read_user}, cty::{size_t, c_void}, maps::{StackTrace, Queue, HashMap, PerfEventArray, PerCpuArray}, bindings::{BPF_F_USER_STACK, bpf_pidns_info, user_pt_regs}
};
use aya_log_ebpf::info;
use tail2_common::{Stack, ConfigKey, MAX_STACK_SIZE};

#[map(name="STACKS")]
static mut STACKS: PerfEventArray<Stack> = PerfEventArray::with_max_entries(1024, 0);

#[map(name="CONFIG")]
static CONFIG: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

static SCRATCH: PerCpuArray<[u8; MAX_STACK_SIZE]> = PerCpuArray::with_max_entries(1, 0);

static EMPTY: [u8; MAX_STACK_SIZE] = [0u8; MAX_STACK_SIZE];
 

#[uprobe(name="malloc_enter")]
pub fn malloc_enter(ctx: ProbeContext) -> u32 {
    let sz: size_t = ctx.arg(0).unwrap();

    info!(&ctx, "malloc: {}", sz);

    let dev = unsafe { CONFIG.get(&(ConfigKey::DEV as u32)) }.copied().unwrap_or(1);
    let ino = unsafe { CONFIG.get(&(ConfigKey::INO as u32)) }.copied().unwrap_or(1);

    let mut ns: bpf_pidns_info = bpf_pidns_info {
        pid: 1,
        tgid: 1,
    };

    unsafe { bpf_get_ns_current_pid_tgid(dev, ino, &mut ns as *mut bpf_pidns_info, core::mem::size_of::<bpf_pidns_info>() as u32); }

    let mut stack = Stack::new();
    let task = unsafe { bpf_get_current_task_btf() };
    let regs: *const user_pt_regs = unsafe { transmute(bpf_task_pt_regs(task)) };
    stack.sp = unsafe { (*regs).sp };
    stack.pc = unsafe { (*regs).pc };

    // try to copy stack
    let st: *const [u8;MAX_STACK_SIZE] = unsafe { transmute(stack.sp) };
    if let Ok(stuff) = unsafe { bpf_probe_read_user(st) } {
        for i in 0..stuff.len() {
            stack.stuff[i] = stuff[i];
        }
    }

    // send the stack over to user land
    unsafe {
        STACKS.output(&ctx, &stack, 0);
    }

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
