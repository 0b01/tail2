use std::fmt::Display;
use std::os::unix::prelude::MetadataExt;
use std::sync::mpsc::channel;

use aya::maps::{StackTraceMap, Queue, HashMap, MapRefMut};
use aya::maps::stack_trace::StackTrace;
use aya::{include_bytes_aligned, Bpf};
use aya::programs::UProbe;
use aya_log::BpfLogger;
use clap::{Parser, Subcommand};
use elf::ElfCache;
use log::{warn};
use proc_mem::ProcMemMap;
use tail2_common::ConfigKey;

mod proc_mem;
mod elf;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Print symbols
    Symbols {
        /// path to elf file
        #[clap(short, long)]
        elf_file: String,
    },
    /// Listen to a PID
    Listen {
        #[clap(short, long)]
        pid: Option<i32>,
    }

}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    match opt.command {
        Commands::Symbols { elf_file } => {
            let elf_cache = ElfCache::build(&[elf_file]);
            dbg!(elf_cache);
            Ok(())
        },
        Commands::Listen { pid: Some(pid) } => {
            run_bpf(pid).await
        },
        _ => {
            Ok(())
        }
    }
}

async fn run_bpf(pid: i32) -> Result<(), anyhow::Error> {
    env_logger::init();
    let (tx, rx) = channel();
    
    ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
        .expect("Error setting Ctrl-C handler");
    

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
    program.attach(Some("malloc"), 0, "libc", pid.try_into()?)?;

    let mut stacks = Queue::<_, [u32; 3]>::try_from(bpf.map_mut("STACKS")?)?;
    let stack_traces = StackTraceMap::try_from(bpf.map_mut("STACK_TRACES")?)?;
    let mut config: HashMap<MapRefMut, u32, u64> = HashMap::try_from(bpf.map_mut("CONFIG")?)?;

    send_device_info(&mut config);

    let mut caches = std::collections::HashMap::<u32, SymCache>::new();

    let mut freqs: std::collections::HashMap<MyStackTrace, u32> = std::collections::HashMap::new();
    println!("Waiting for Ctrl-C...");

    loop {
        if let Ok([pid, utrace_id, _sz]) = stacks.pop(0) {
            if let Ok(stack_trace) = stack_traces.get(&(utrace_id as u32), 0) {
                let syms = caches.entry(pid).or_insert_with(|| SymCache::build(pid));
                let st = MyStackTrace::from(stack_trace, syms);
                let freq = freqs.entry(st).or_insert(0);
                *freq += 1;
            }
        }

        if rx.try_recv().is_ok() {
            println!("Got it! Exiting..."); 
            for (st, n) in freqs {
                println!("{} - {}\n", st, n);
            }
            break;
        }
    }

    Ok(())
}

pub struct SymCache {
    pub proc_map: ProcMemMap,
    pub elf_cache: ElfCache,
}

impl SymCache {
    pub fn build(pid: u32) -> Self {
        let proc_map = ProcMemMap::from_process_id(pid).unwrap();
        let paths: Vec<String> = proc_map.entries.iter().map(|i| i.object_path.to_owned()).collect();
        let elf_cache = ElfCache::build(&paths);

        Self {
            proc_map,
            elf_cache,
        }
    }
}


#[derive(Hash, Eq, PartialEq, Debug)]
struct MyStackTrace {
    frames: Vec<(String, u64, String)>,
}

impl MyStackTrace {
    fn from(trace: StackTrace, syms: &SymCache) -> Self {
        let frames = trace.frames().iter().map(|f| {
            if let Some(res) = syms.proc_map.lookup(f.ip) {
                let addr = res.address;
                let name = syms.elf_cache.map.get(&res.object_path).and_then(|c| c.find(addr)).unwrap_or("".to_owned());
                (res.object_path, addr, name)
            } else {
                ("".to_owned(), 0, "".to_owned())
            }
        }).collect();

        Self {
            frames,
        }
    }
}

impl Display for MyStackTrace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (obj, offset, name) in &self.frames {
            let _ = writeln!(f, "<{}> {}+{:#x}", name, obj, offset);
        }

        Ok(())
    }
}

fn send_device_info(config: &mut HashMap<MapRefMut, u32, u64>) {
    let stats = std::fs::metadata("/proc/self/ns/pid").unwrap();
    let dev = stats.dev();
    let ino = stats.ino();
    config.insert(ConfigKey::DEV as u32, dev, 0).unwrap();
    config.insert(ConfigKey::INO as u32, ino, 0).unwrap();
}