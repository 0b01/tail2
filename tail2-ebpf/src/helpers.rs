use aya_bpf::{bindings::{bpf_pidns_info, task_struct}, helpers::{bpf_get_ns_current_pid_tgid, bpf_get_current_task}};
use tail2_common::ConfigMapKey;

use crate::maps::CONFIG;

pub fn get_pid_tgid() -> bpf_pidns_info {
    let dev = unsafe { CONFIG.get(&(ConfigMapKey::DEV as u32)) }.copied().unwrap_or(1);
    let ino = unsafe { CONFIG.get(&(ConfigMapKey::INO as u32)) }.copied().unwrap_or(1);
    let task: *mut task_struct = unsafe { bpf_get_current_task() as _ };

    let mut ns: bpf_pidns_info = unsafe { core::mem::zeroed() };
    // TODO: make a nice wrapper for this so it'll always get initialized correctly.
    unsafe { bpf_get_ns_current_pid_tgid(dev, ino, &mut ns as *mut bpf_pidns_info, core::mem::size_of::<bpf_pidns_info>() as u32); }
    ns
}
