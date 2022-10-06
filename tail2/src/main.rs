use std::os::unix::prelude::MetadataExt;

use aya::maps::{StackTraceMap, Queue, HashMap, MapRefMut};
use aya::maps::stack_trace::StackTrace;
use aya::{include_bytes_aligned, Bpf};
use aya::programs::UProbe;
use aya_log::BpfLogger;
use clap::Parser;
use log::{warn};
use proc_mem::ProcMemMap;
use tail2_common::ConfigKey;

mod proc_mem;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tail2"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tail2"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut UProbe = bpf.program_mut("malloc_enter").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("malloc"), 0, "libc", opt.pid.try_into()?)?;

    let mut stacks = Queue::<_, [u64; 2]>::try_from(bpf.map_mut("STACKS")?)?;
    let stack_traces = StackTraceMap::try_from(bpf.map_mut("STACK_TRACES")?)?;
    let mut config: HashMap<MapRefMut, u32, u64> = HashMap::try_from(bpf.map_mut("CONFIG")?)?;

    send_device_info(&mut config);

    loop {
        match stacks.pop(0) {
            Ok([pid_tgid, utrace_id]) => {
                let tgid = pid_tgid >> 32;
                println!("{:#x}", pid_tgid);
                let proc_map = ProcMemMap::from_process_id(tgid as u32).unwrap();
                if let Ok(trace) = stack_traces.get(&(utrace_id as u32), 0) {
                    print_stack(&proc_map, &trace);
                }
            },
            _ => {
            }
        }
    }
}


fn print_stack(proc_map: &ProcMemMap, stack_trace: &StackTrace) {
    for frame in stack_trace.frames() {
        let res = proc_map.lookup(frame.ip).unwrap();

        println!(
            "{}:{:#x}",
            res.object_path().unwrap().display(),
            res.address(),
        );
    }
}

fn send_device_info(config: &mut HashMap<MapRefMut, u32, u64>) {
    let stats = std::fs::metadata("/proc/self/ns/pid").unwrap();
    let dev = stats.dev();
    let ino = stats.ino();
    config.insert(ConfigKey::DEV as u32, dev, 0); // dev
    config.insert(ConfigKey::INO as u32, ino, 0); // ino
}