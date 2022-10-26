use std::mem::size_of;
use std::os::unix::prelude::MetadataExt;
use std::process::{self, exit};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::channel;
use std::thread;

use aya::maps::perf::{AsyncPerfEventArray};
use aya::maps::{HashMap, PerfEventArray};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya::programs::{UProbe, PerfEvent, SamplePolicy, PerfTypeId, PerfEventScope, perf_event};
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use libc::getuid;
use log::{info, error};
use procinfo::processes::Processes;
use std::sync::RwLock;
use unwinding::MyUnwinderAarch64;
use crate::stacktrace::MyStackTrace;
use crate::symbolication::elf::ElfCache;
use framehop::aarch64::{UnwinderAarch64, CacheAarch64};
use tail2_common::{ConfigKey, Stack};
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
    let mut info = Processes::new();
    info.populate();
    let info = Arc::new(RwLock::new(info));

    match opt.command {
        Commands::Info { } => {
            info!("{:#?}", info.read());
            Ok(())
        },
        Commands::Symbols { elf_file } => {
            let elf_cache = ElfCache::build(&[elf_file]);
            info!("{:#?}", elf_cache);
            Ok(())
        },
        Commands::Sample { pid } => {
            let pid = pid.map(|i| if i == 0 {process::id() as i32} else {i});
            let mut bpf = load_bpf()?;
            BpfLogger::init(&mut bpf).unwrap();

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
                    SamplePolicy::Frequency(10_000),
                )?;
            }

            run_bpf(&mut bpf, pid, info).await
        },
        Commands::Alloc { pid } => {
            let pid = pid.map(|i| if i == 0 {process::id() as i32} else {i});
            let mut bpf = load_bpf()?;
            BpfLogger::init(&mut bpf).unwrap();

            let program: &mut UProbe = bpf.program_mut("malloc_enter").unwrap().try_into().unwrap();
            program.load().unwrap();
            program.attach(Some("malloc"), 0, "libc", pid).unwrap();

            run_bpf(&mut bpf, pid, info).await
        }
    }
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

async fn run_bpf(bpf: &mut Bpf, pid: Option<i32>, proc_maps: Arc<RwLock<Processes>>) -> Result<()> {
    let mut config: HashMap<_, u32, u64> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap()).unwrap();
    // send device info
    let stats = std::fs::metadata("/proc/self/ns/pid").unwrap();
    let dev = stats.dev();
    let ino = stats.ino();
    config.insert(ConfigKey::DEV as u32, dev, 0).unwrap();
    config.insert(ConfigKey::INO as u32, ino, 0).unwrap();

    // open bpf maps
    let mut stacks = AsyncPerfEventArray::try_from(bpf.take_map("STACKS").unwrap()).unwrap();
    let mut new_procs = AsyncPerfEventArray::try_from(bpf.take_map("NEW_PROCS").unwrap()).unwrap();

    let count = Arc::new(AtomicU64::new(0));
    let (tx, rx) = channel::<Stack>();

    // receiver thread
    let proc_maps_ = proc_maps.clone();
    thread::spawn(move || {
        let mut unw = MyUnwinderAarch64::new();
        for st in rx.iter() {
            let mut maps = proc_maps_.write();
            if let Ok(proc_map) = maps.unwrap().entry(st.pid() as i32) {
                let frames = unw.unwind(st, &proc_map.maps);
            }
        }
    });

    // listen to bpf perf buf, send stacks to tx
    for cpu_id in online_cpus().unwrap() {
        let mut buf = stacks.open(cpu_id, Some(1024)).unwrap();
        
        let proc_maps = proc_maps.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut buffers = (0..60)
                .map(|_| BytesMut::with_capacity(size_of::<Stack>()))
                .collect::<Vec<_>>();
    
            loop {
                // poll for events
                let events = buf.read_events(&mut buffers).await.unwrap();
    
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let st = unsafe { *std::mem::transmute::<_, *const Stack>(buf.as_ptr()) };
                    tx.send(st);
                }
            }
        });
    }
    
    signal::ctrl_c().await.expect("failed to listen for event");
    info!("exiting!");
    Ok(())
}