#![allow(dead_code)]

use std::borrow::Borrow;
use std::mem::size_of;
use std::os::unix::prelude::MetadataExt;
use std::process::{self, exit};
use std::sync::{Arc, Condvar};
use std::sync::atomic::AtomicU64;
use std::thread;
use std::time::Duration;

use aya::maps::perf::{AsyncPerfEventArray};
use aya::maps::{HashMap, PerfEventArray, MapData};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya::programs::{UProbe, PerfEvent, SamplePolicy, PerfTypeId, PerfEventScope, perf_event};
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use libc::getuid;
use log::{info, error};
use procinfo::processes::Processes;
use tail2_common::runtime_type::RuntimeType;
use tokio::sync::watch::Receiver;
use tokio::sync::{futures, Mutex, watch, RwLock, mpsc};
use tokio::task::JoinHandle;
use unwinding::MyUnwinderAarch64;
use crate::stacktrace::MyStackTrace;
use crate::symbolication::elf::ElfCache;
use framehop::aarch64::{UnwinderAarch64, CacheAarch64};
use tail2_common::{ConfigMapKey, Stack, InfoMapKey};
use tokio::{task, signal};
use aya_log::BpfLogger;
use anyhow::Result;

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

    let mut pid_info: HashMap<_, u32, RuntimeType> = HashMap::try_from(bpf.map_mut("PIDS").unwrap()).unwrap();

    // for waiting Ctrl-C signal
    let (stop_tx, stop_rx) = watch::channel(false);

    // refresh pid info table
    // HAX: extend lifetime to 'static
    let mut pid_info = unsafe { std::mem::transmute::<HashMap<&mut MapData, u32, RuntimeType>, HashMap<&'static mut MapData, u32, RuntimeType>>(pid_info) };
    let proc_maps = Arc::new(RwLock::new(Processes::new()));

    let proc_maps2 = proc_maps.clone();
    let mut stop_rx2 = stop_rx.clone();
    tokio::spawn(async move {
        loop {
            let mut p = proc_maps2.write().await;
            p.populate();
        
            // copy to map
            for (pid, nfo) in &p.processes {
                let rt = nfo.rt;
                pid_info.insert(*pid as u32, rt, 0);
            }

            // drop the lock so we don't hog other tasks
            drop(p);

            // sleep for 1 sec
            tokio::select! {
                _ = tokio::time::sleep(Duration::new(1, 0)) => (),
                _ = stop_rx2.changed() => break,
            }
            
        }
    });

    match opt.command {
        Commands::Info { } => {
            info!("{:#?}", proc_maps.read().await);
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
                    SamplePolicy::Frequency(4_000),
                )?;
            }

            let ts = run_bpf(&mut bpf, pid, proc_maps, stop_rx)?;

            signal::ctrl_c().await.expect("failed to listen for event");
            info!("exiting");
            stop_tx.send(true)?;
            for t in ts { tokio::join!(t); }
        },
        Commands::Alloc { pid } => {
            let pid = pid.map(|i| if i == 0 {process::id() as i32} else {i});
            let mut bpf = load_bpf()?;

            let program: &mut UProbe = bpf.program_mut("malloc_enter").unwrap().try_into().unwrap();
            program.load().unwrap();
            program.attach(Some("malloc"), 0, "libc", pid).unwrap();

            let ts = run_bpf(&mut bpf, pid, proc_maps, stop_rx)?;

            signal::ctrl_c().await.expect("failed to listen for event");
            info!("exiting");
            stop_tx.send(true)?;
            for t in ts { tokio::join!(t); }
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

fn run_bpf(bpf: &mut Bpf, pid: Option<i32>, proc_maps: Arc<RwLock<Processes>>, stop_rx: Receiver<bool>) -> Result<Vec<JoinHandle<()>>> {
    // send device info
    let mut config: HashMap<_, u32, u64> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap()).unwrap();
    let stats = std::fs::metadata("/proc/self/ns/pid").unwrap();
    let dev = stats.dev();
    let ino = stats.ino();
    config.insert(ConfigMapKey::DEV as u32, dev, 0).unwrap();
    config.insert(ConfigMapKey::INO as u32, ino, 0).unwrap();

    // open bpf maps
    let mut stacks = AsyncPerfEventArray::try_from(bpf.take_map("STACKS").unwrap()).unwrap();

    let count = Arc::new(AtomicU64::new(0));
    let (tx, mut rx) = mpsc::channel::<Stack>(2048);

    // receiver thread
    let proc_maps_ = proc_maps.clone();
    let mut ts = vec![];
    let t = tokio::spawn(async move {
        let mut unw = MyUnwinderAarch64::new();
        let mut c = 0;
        while let Some(st) = rx.recv().await {
            if let Ok(proc_map) = proc_maps_.write().await.entry(st.pid() as i32) {
                let frames = unw.unwind(st, &proc_map.maps);

                c += 1;
            }
        }

        info!("Processed: {c} stacks");
    });
    ts.push(t);

    // listen to bpf perf buf, send stacks to tx
    for cpu_id in online_cpus().unwrap() {
        let mut buf = stacks.open(cpu_id, Some(1024)).unwrap();
        
        let proc_maps = proc_maps.clone();
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