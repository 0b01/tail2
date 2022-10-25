use std::mem::size_of;
use std::os::unix::prelude::MetadataExt;
use std::process;
use std::sync::Arc;

use aya::maps::perf::{AsyncPerfEventArray};
use aya::maps::HashMap;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya::programs::{UProbe, PerfEvent, SamplePolicy, PerfTypeId, PerfEventScope, perf_event};
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use log::info;
use procinfo::processes::Processes;
use tokio::sync::RwLock;
use unwinding::MyUnwinderAarch64;
use crate::stacktrace::MyStackTrace;
use crate::symbolication::elf::ElfCache;
use framehop::aarch64::{UnwinderAarch64, CacheAarch64};
use tail2_common::{ConfigKey, Stack};
use tokio::{task, signal};
use aya_log::BpfLogger;

pub mod procinfo;
pub mod unwinding;
pub mod symbolication;
pub mod stacktrace;

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
    /// Listen to system events
    Listen {
        #[clap(short, long)]
        pid: Option<i32>,
    },
    /// Print system information
    Info {
    },
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    let mut info = Processes::new();
    info.populate();
    let info = Arc::new(RwLock::new(info));

    match opt.command {
        Commands::Info { } => {
            dbg!(info.read().await);
            Ok(())
        },
        Commands::Symbols { elf_file } => {
            let elf_cache = ElfCache::build(&[elf_file]);
            dbg!(elf_cache);
            Ok(())
        },
        Commands::Listen { pid } => {
            let pid = pid.map(|i| if i == 0 {process::id() as i32} else {i});
            run_bpf(pid, info).await
        },
    }
}

async fn run_bpf(pid: Option<i32>, proc_maps: Arc<RwLock<Processes>>) -> Result<(), anyhow::Error> {
    env_logger::init();

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tail2"
    )).unwrap();
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tail2"
    )).unwrap();

    BpfLogger::init(&mut bpf).unwrap();

        let program: &mut UProbe = bpf.program_mut("malloc_enter").unwrap().try_into().unwrap();
        program.load().unwrap();
        program.attach(Some("malloc"), 0, "libc", pid).unwrap();

        // let program: &mut PerfEvent = bpf.program_mut("capture_stack").unwrap().try_into().unwrap();
        // program.load().unwrap();
        // for cpu in online_cpus()? {
        //     let scope = pid
        //         .map(|pid| PerfEventScope::OneProcessOneCpu { cpu, pid  })
        //         .unwrap_or_else(|| PerfEventScope::AllProcessesOneCpu { cpu });
        //     program.attach(
        //         PerfTypeId::Software,
        //         perf_event::perf_sw_ids::PERF_COUNT_SW_TASK_CLOCK as u64,
        //         scope,
        //         SamplePolicy::Frequency(10_000),
        //     )?;
        // }

    let mut config: HashMap<_, u32, u64> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap()).unwrap();
    // send device info
    let stats = std::fs::metadata("/proc/self/ns/pid").unwrap();
    let dev = stats.dev();
    let ino = stats.ino();
    config.insert(ConfigKey::DEV as u32, dev, 0).unwrap();
    config.insert(ConfigKey::INO as u32, ino, 0).unwrap();

    let mut stacks = AsyncPerfEventArray::try_from(bpf.take_map("STACKS").unwrap()).unwrap();

    for cpu_id in online_cpus().unwrap() {
        let mut buf = stacks.open(cpu_id, None).unwrap();
        
        let proc_maps = proc_maps.clone();
        task::spawn(async move {
            let mut unw = MyUnwinderAarch64::new();

            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(size_of::<Stack>()))
                .collect::<Vec<_>>();
    
            loop {
                // wait for events
                let events = buf.read_events(&mut buffers).await.unwrap();
    
                // events.read contains the number of events that have been read,
                // and is always <= buffers.len()
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let st = unsafe { *std::mem::transmute::<_, *const Stack>(buf.as_ptr()) };

                    let mut maps = proc_maps.write().await;
                    if let Ok(proc_map) = maps.entry(st.pid() as i32) {
                        let frames = unw.unwind(st, &proc_map.maps);
                        let stacktrace = MyStackTrace::from_frames(&frames, &proc_map.maps);
                        dbg!(stacktrace);
                    }
                }
            }
        });
    }
    
    signal::ctrl_c().await.expect("failed to listen for event");

    info!("exiting!");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example() {

        let mut unwinder = UnwinderAarch64::new();
        let mut unw_cache = CacheAarch64::<_>::new();

        add_module_to_unwinder(
            &mut unwinder,
            "/home/g/tail2/testapp/malloc/a.out".as_bytes(),
            0,
            0xaaaac6cd0000,
            0x1000,
            None,
            None,
        );

        add_module_to_unwinder(
            &mut unwinder,
            "/usr/lib/aarch64-linux-gnu/libc.so.6".as_bytes(),
            0,
            0xffff87770000,
            0xffff878f9000 - 0xffff87770000,
            None,
            None,
        );

        let pc = 281473445385793;
        let sp = 281474403929088;
        let fp = 281474403929088;
        let lr = 187650854029324;

        let mut iter = unwinder.iter_frames(
            pc,
            UnwindRegsAarch64::new(lr, sp, fp),
            &mut unw_cache,
            &mut read_stack,
        );

    }
}