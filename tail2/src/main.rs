#![allow(dead_code)]

use std::borrow::Borrow;
use std::mem::size_of;
use std::os::unix::prelude::MetadataExt;
use std::process::{self, exit};
use std::sync::{Arc, Condvar};
use std::sync::atomic::AtomicU64;
use std::time::{Duration, SystemTime};

use aya::maps::perf::{AsyncPerfEventArray};
use aya::maps::{HashMap, PerfEventArray, MapData};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya::programs::{UProbe, PerfEvent, SamplePolicy, PerfTypeId, PerfEventScope, perf_event};
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use libc::getuid;
use log::{info, error};
use tail2_common::module::Module;
use tail2_common::procinfo::ProcInfo;
use tail2_common::runtime_type::RuntimeType;
use tokio::sync::watch::Receiver;
use tokio::sync::{futures, Mutex, watch, RwLock, mpsc};
use tokio::task::JoinHandle;
#[cfg(debug_assertions)]
use crate::debugstacktrace::DebugStackTrace;
use crate::processes::Processes;
use crate::symbolication::elf::ElfCache;
use framehop::aarch64::{UnwinderAarch64, CacheAarch64};
use tail2_common::{ConfigMapKey, Stack, InfoMapKey};
use tokio::{task, signal};
use aya_log::BpfLogger;
use anyhow::Result;

pub mod processes;
pub mod unwinding;
pub mod symbolication;
#[cfg(debug_assertions)]
pub mod debugstacktrace;

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
    /// Sample
    Sample {
        #[clap(short, long)]
        pid: Option<i32>,
    },
    /// Listen to alloc events
    Alloc {
        #[clap(short, long)]
        pid: Option<i32>,
    },
    /// Print system information
    Info {
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // init logger
    let env = env_logger::Env::default()
        .filter_or("LOG_LEVEL", "debug")
        .write_style_or("LOG_STYLE", "always");
    env_logger::init_from_env(env);

    // make sure we are running with root privileges
    let uid = unsafe { getuid() };
    if uid != 0 {
        error!("tail2 be be run with root privileges!");
        exit(-1);
    }

    let opt = Opt::parse();

    let mut bpf = load_bpf()?;
    BpfLogger::init(&mut bpf).unwrap();

    // for waiting Ctrl-C signal
    let (stop_tx, stop_rx) = watch::channel(false);

    let mut pid_info: HashMap<_, u32, ProcInfo> = HashMap::try_from(bpf.map_mut("PIDS").unwrap()).unwrap();
    let mut pid_info = unsafe { std::mem::transmute::<HashMap<&mut MapData, u32, ProcInfo>, HashMap<&'static mut MapData, u32, ProcInfo>>(pid_info) };
    let mut mod_info: HashMap<_, u32, Module> = HashMap::try_from(bpf.map_mut("MODS").unwrap()).unwrap();
    let mut mod_info = unsafe { std::mem::transmute::<HashMap<&mut MapData, u32, Module>, HashMap<&'static mut MapData, u32, Module>>(mod_info) };

    // refresh pid info table
    // HAX: extend lifetime to 'static
    let mut stop_rx2 = stop_rx.clone();
    tokio::spawn(async move {
        loop {
            let mut p = Processes::new();
            p.populate();
        
            // copy to maps
            for (pid, nfo) in p.processes {
                pid_info.insert(pid as u32, nfo, 0);
            }

            // sleep for 1 sec
            tokio::select! {
                _ = tokio::time::sleep(Duration::new(1, 0)) => (),
                _ = stop_rx2.changed() => break,
            }
        }
    });

    match opt.command {
        Commands::Info { } => {
            info!("{:#?}", Processes::new());
            return Ok(());
        },
        Commands::Symbols { elf_file } => {
            let elf_cache = ElfCache::build(&[elf_file]);
            info!("{:#?}", elf_cache);
            return Ok(());
        },
        Commands::Sample { pid } => {
            let pid = pid.map(|i| if i == 0 {process::id() as i32} else {i});

            let program: &mut PerfEvent = bpf.program_mut("capture_stack").unwrap().try_into().unwrap();
            program.load().unwrap();
            for cpu in online_cpus()? {
                let scope = pid
                    .map(|pid| PerfEventScope::OneProcessOneCpu { cpu, pid: pid as u32  })
                    .unwrap_or_else(|| PerfEventScope::AllProcessesOneCpu { cpu });
                program.attach(
                    PerfTypeId::Software,
                    perf_event::perf_sw_ids::PERF_COUNT_SW_TASK_CLOCK as u64,
                    scope,
                    SamplePolicy::Period(4_000_000),
                )?;
            }

            let ts = run_bpf(&mut bpf, pid, stop_rx)?;

            signal::ctrl_c().await.expect("failed to listen for event");
            info!("exiting");
            stop_tx.send(true)?;
            for t in ts { let _ = tokio::join!(t); }
        },
        Commands::Alloc { pid } => {
            let pid = pid.map(|i| if i == 0 {process::id() as i32} else {i});

            let program: &mut UProbe = bpf.program_mut("malloc_enter").unwrap().try_into().unwrap();
            program.load().unwrap();
            program.attach(Some("malloc"), 0, "libc", pid).unwrap();

            let ts = run_bpf(&mut bpf, pid, stop_rx)?;

            signal::ctrl_c().await.expect("failed to listen for event");
            info!("exiting");
            stop_tx.send(true)?;
            for t in ts { let _ = tokio::join!(t); }
        }
    }

    // #[cfg(debug_assertions)]
    {
        let info: HashMap<_, u32, u64> = HashMap::try_from(bpf.map("RUN_INFO").unwrap()).unwrap();
        info!("Sent: {} stacks", info.get(&(InfoMapKey::SentStackCount as u32), 0).unwrap());
    }

    Ok(())
}

fn load_bpf() -> Result<Bpf> {
    #[cfg(debug_assertions)]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tail2"
    ))?;

    #[cfg(not(debug_assertions))]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tail2"
    ))?;
    Ok(bpf)
}

fn run_bpf(bpf: &mut Bpf, pid: Option<i32>, stop_rx: Receiver<bool>) -> Result<Vec<JoinHandle<()>>> {
    // send device info
    let mut config: HashMap<_, u32, u64> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap()).unwrap();
    let stats = std::fs::metadata("/proc/self/ns/pid").unwrap();
    let dev = stats.dev();
    let ino = stats.ino();
    config.insert(ConfigMapKey::DEV as u32, dev, 0).unwrap();
    config.insert(ConfigMapKey::INO as u32, ino, 0).unwrap();

    // open bpf maps
    let mut stacks = AsyncPerfEventArray::try_from(bpf.take_map("STACKS").unwrap()).unwrap();

    let (tx, mut rx) = mpsc::channel::<Stack>(2048);

    // receiver thread
    let mut ts = vec![];
    let mut total_time = Duration::new(0, 0);
    let t = tokio::spawn(async move {
        let mut c = 0;
        while let Some(st) = rx.recv().await {
            let start_time = SystemTime::now();

            let elapsed = SystemTime::now().duration_since(start_time).unwrap();
            total_time += elapsed;
            c += 1;
        }

        let avg_t = total_time / c;
        info!("Processed: {c} stacks. {avg_t:?}/st");
    });
    ts.push(t);

    // listen to bpf perf buf, send stacks to tx
    for cpu_id in online_cpus().unwrap() {
        let mut buf = stacks.open(cpu_id, Some(1024)).unwrap();
        
        let tx = tx.clone();
        let mut stop_rx2 = stop_rx.clone();
        let t = tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(size_of::<Stack>()))
                .collect::<Vec<_>>();

            loop {
                // poll for events
                tokio::select! {
                    evts = buf.read_events(&mut buffers) => {
                        let events = evts.unwrap();
                        for i in 0..events.read {
                            let buf = &mut buffers[i];
                            let st = unsafe { *std::mem::transmute::<_, *const Stack>(buf.as_ptr()) };
                            if let Err(_) = tx.try_send(st) {
                                error!("slow");
                            }
                        }
                    },
                    _ = stop_rx2.changed() => break,
                };
            }
        });
        ts.push(t);
    }
    // Drop tx from main thread, so when producers join, consumer thread will also join.
    drop(tx);
    Ok(ts)
}