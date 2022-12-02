use anyhow::Result;
use aya::maps::{AsyncPerfEventArray, HashMap, StackTraceMap};
use aya::programs::{PerfEvent, PerfEventScope, PerfTypeId, SamplePolicy, UProbe, perf_event};
use aya::util::online_cpus;
use bytes::BytesMut;
use log::{error, info, debug};
use nix::sys::ptrace;
use nix::sys::signal::Signal::{SIGSTOP, SIGCONT};
use nix::sys::signal::kill;
use nix::unistd::{getuid, Pid, getpid};
use tokio::time::sleep;
use crate::dto::resolved_bpf_sample::ResolvedBpfSample;
use tail2_common::bpf_sample::BpfSample;
use tail2_common::{ConfigMapKey, NativeStack};
use tokio::signal;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{exit, Command, Child};
use std::{mem::size_of, sync::Arc};
use std::os::unix::prelude::MetadataExt;
use std::time::{SystemTime};
use tokio::sync::watch;

use std::time::Duration;

use aya::maps::{MapData};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use crate::symbolication::module_cache::ModuleCache;
use tail2_common::procinfo::ProcInfo;
use tokio::sync::watch::Receiver;
use tokio::sync::Mutex;
use tail2_common::RunStatsKey;
use anyhow::{Context};

use crate::processes::Processes;

use crate::client::api_client::ApiStackEndpointClient;

pub(crate) fn open_and_subcribe(bpf: &mut Bpf, tx: mpsc::Sender<BpfSample>, stop_rx: watch::Receiver<()>, ts: &mut Vec<JoinHandle<()>>) {
    // open bpf maps
    let mut stacks = AsyncPerfEventArray::try_from(bpf.take_map("STACKS").unwrap()).unwrap();

    // listen to bpf perf buf, send stacks to tx
    for cpu_id in online_cpus().unwrap() {
        let mut buf = stacks.open(cpu_id, Some(1024)).unwrap();
        
        let tx = tx.clone();
        let mut stop_rx2 = stop_rx.clone();
        let t = tokio::spawn(async move {
            let mut buffers = (0..1)
                .map(|_| BytesMut::with_capacity(size_of::<BpfSample>()))
                .collect::<Vec<_>>();

            loop {
                // poll for events
                tokio::select! {
                    evts = buf.read_events(&mut buffers) => {
                        let events = evts.unwrap();
                        for buf in buffers.iter_mut().take(events.read) {
                            let st: BpfSample = unsafe { *std::mem::transmute::<_, *const _>(buf.as_ptr()) };
                            // dbg!(&st);

                            if tx.try_send(st).is_err() {
                                error!("slow");
                            }
                        }
                    },
                    _ = stop_rx2.changed() => {
                        break;
                    },
                };
            }
        });
        ts.push(t);
    }

}

pub(crate) fn run_bpf(
    bpf: &mut Bpf,
    stop_rx: watch::Receiver<()>,
    module_cache: Arc<Mutex<ModuleCache>>,
    output_tx: Option<mpsc::Sender<BpfSample>>
) -> Result<Vec<JoinHandle<()>>> {
    // send device info
    let mut config: HashMap<_, u32, u64> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap()).unwrap();
    let stats = std::fs::metadata("/proc/self/ns/pid").unwrap();
    config.insert(ConfigMapKey::DEV as u32, stats.dev(), 0).unwrap();
    config.insert(ConfigMapKey::INO as u32, stats.ino(), 0).unwrap();

    let (tx, mut rx) = mpsc::channel::<BpfSample>(2048);

    let cli = Arc::new(Mutex::new(ApiStackEndpointClient::new(
        "http://0.0.0.0:8000/stack",
        Arc::clone(&module_cache),
        400,
    )));

    let kernel_stacks = StackTraceMap::try_from(bpf.take_map("KERNEL_STACKS").unwrap()).unwrap();
    let ksyms = aya::util::kernel_symbols().unwrap();

    // receiver thread
    let mut ts = vec![];
    let mut total_time = Duration::new(0, 0);
    let t = tokio::spawn(async move {
        let mut c = 0;
        while let Some(st) = rx.recv().await {
            let start_time = SystemTime::now();

            // dbg!(&st);
            if let Some(ref output_tx) = output_tx {
                output_tx.send(st).await.unwrap();
            }

            let st = ResolvedBpfSample::resolve(st, &kernel_stacks, &ksyms);

            let cli2 = Arc::clone(&cli);
            tokio::spawn(async move {
                if let Err(e) = cli2.lock().await.post_stack(st).await {
                    error!("sending stack failed: {}", e.to_string());
                }
            });

            let elapsed = SystemTime::now().duration_since(start_time).unwrap();
            total_time += elapsed;
            c += 1;
        }

        let _ = cli.lock().await.flush().await;

        let avg_t = total_time / c;
        info!("Processed: {c} stacks. {avg_t:?}/st");
    });
    ts.push(t);

    open_and_subcribe(bpf, tx, stop_rx, &mut ts);

    Ok(ts)
}

/// make sure we are running with root privileges
fn ensure_root() {
    let uid = getuid().as_raw();
    if uid != 0 {
        error!("tail2 be be run with root privileges!");
        exit(-1);
    }
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        anyhow::bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn get_pid<'a>(pid: Option<u32>, command: Option<String>) -> Result<Option<i32>, Child> {
    match (pid, command) {
        (None, None) => Ok(None),
        (None, Some(cmd)) => {
            let path = PathBuf::from(cmd);
            let current_dir = std::env::current_dir().expect("unable to get current dir");
            debug!("Current directory: {}", current_dir.display());
            let path = fs::canonicalize(path).expect("cannot canonicalize path");
            info!("Launching child process: `{:?}`", path);
            let mut cmd = Command::new(path);
            unsafe {
                cmd.pre_exec(|| {
                    ptrace::traceme().or(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "ptrace TRACEME failed",
                    )))
                });
            }
            match cmd.spawn() {
                Ok(child) => {
                    let pid = child.id();
                    Err(child)
                }
                Err(e) => panic!("{}", e.to_string()),
            }
        },
        (Some(pid), None) => Ok(Some(pid as i32)),
        (Some(_), Some(_)) => panic!("supply one of --pid, --command")
    }
}


pub fn get_pid_child(pid: Option<u32>, command: Option<String>, child: &mut Option<Child>) -> Option<u32> {
    match get_pid(pid, command) {
        Err(c) => {
            let ret = c.id() as u32;
            *child = Some(c);
            Some(ret)
        }
        Ok(Some(pid)) => Some(pid as u32),
        Ok(None) => None
    }
}

pub async fn bpf_init() -> Result<Bpf> {
    // init logger
    let env = env_logger::Env::default()
        .filter_or("LOG_LEVEL", "info")
        .write_style_or("LOG_STYLE", "always");

    env_logger::init_from_env(env);
    ensure_root();
    bump_memlock_rlimit()?;
    let mut bpf = load_bpf()?;

    BpfLogger::init(&mut bpf).unwrap();

    Ok(bpf)
}

pub async fn attach_perf_event(bpf: &mut Bpf, pid: Option<u32>, period: u64) -> Result<()> {
    let program: &mut PerfEvent = bpf.program_mut("capture_stack").unwrap().try_into().unwrap();
    match program.load() {
        Ok(_) => {},
        Err(e) => {
            error!("{}", e.to_string());
            panic!();
        }
    }

    for cpu in online_cpus()? {
        let scope = match pid {
            Some(pid) => PerfEventScope::OneProcessOneCpu { cpu, pid: pid as u32 },
            None => PerfEventScope::AllProcessesOneCpu { cpu },
        };
        program.attach(
            PerfTypeId::Software,
            perf_event::perf_sw_ids::PERF_COUNT_SW_TASK_CLOCK as u64,
            scope,
            SamplePolicy::Period(period),
        )?;
    }

    Ok(())
}


pub async fn attach_uprobe(bpf: &mut Bpf, uprobe: &str, pid: Option<u32>) -> Result<()> {
    let program: &mut UProbe = bpf.program_mut("malloc_enter").unwrap().try_into().unwrap();
    match program.load() {
        Ok(_) => {},
        Err(e) => {
            error!("{}", e.to_string());
            panic!();
        }
    }

    let mut uprobe = uprobe.split(":");
    let src = uprobe.next().unwrap();
    let func = uprobe.next().unwrap();
    let _uprobe_link = program.attach(Some(func), 0, src, pid.map(|i| i as i32)).unwrap();
    info!("loaded");
    Ok(())
}

pub async fn run_until_exit(bpf: &mut aya::Bpf, module_cache: Arc<Mutex<ModuleCache>>, child: Option<Child>, output_tx: Option<mpsc::Sender<BpfSample>>) -> Result<()> {
    // for awaiting Ctrl-C signal
    let (stop_tx, stop_rx) = watch::channel(());
    if child.is_some() {
        proc_refresh_once(bpf, Arc::clone(&module_cache)).await.unwrap();
    } else {
        spawn_proc_refresh(bpf, stop_rx.clone(), Arc::clone(&module_cache)).await;
    }

    let tasks = run_bpf(bpf, stop_rx, module_cache, output_tx)?;

    if let Some(mut c) = child {
        info!("resuming child");
        let pid = Pid::from_raw(c.id() as i32);
        // nix::sys::wait::waitpid(pid, None).unwrap();
        ptrace::cont(pid, None).unwrap();
        c.wait().expect("unable to execute child");
        info!("child exited");
    } else {
        signal::ctrl_c().await.expect("failed to listen for event");
    }

    info!("exiting");
    stop_tx.send(())?;
    for t in tasks { let _ = tokio::join!(t); }
    print_stats(bpf).await?;

    Ok(())
}

async fn proc_refresh_inner(pid_info: &mut HashMap<&mut MapData, u32, ProcInfo>, module_cache: Arc<Mutex<ModuleCache>>) {
    let module_cache = Arc::clone(&module_cache);
    let mut processes = Processes::new(module_cache);
    if let Ok(()) = processes.refresh().await {
        dbg!(processes.processes.keys().len());
        // copy to maps
        for (pid, nfo) in &processes.processes {
            let nfo = nfo.as_ref();
            pid_info.insert(*pid as u32, nfo, 0).unwrap();
        }
    }
}

pub async fn proc_refresh_once(bpf: &mut Bpf, module_cache: Arc<Mutex<ModuleCache>>) -> Result<()> {
    let pid_info: HashMap<_, u32, ProcInfo> = HashMap::try_from(bpf.map_mut("PIDS").unwrap()).unwrap();
    // HACK: extend lifetime to 'static
    let mut pid_info = unsafe { std::mem::transmute::<HashMap<&mut MapData, u32, ProcInfo>, HashMap<&'static mut MapData, u32, ProcInfo>>(pid_info) };

    proc_refresh_inner(&mut pid_info, module_cache.clone()).await;
    Ok(())
}

// TODO: don't refresh, listen to mmap and execve calls
pub(crate) async fn spawn_proc_refresh(bpf: &mut Bpf, mut stop_rx: Receiver<()>, module_cache: Arc<Mutex<ModuleCache>>) {
    let pid_info: HashMap<_, u32, ProcInfo> = HashMap::try_from(bpf.map_mut("PIDS").unwrap()).unwrap();
    // HACK: extend lifetime to 'static
    let mut pid_info = unsafe { std::mem::transmute::<HashMap<&mut MapData, u32, ProcInfo>, HashMap<&'static mut MapData, u32, ProcInfo>>(pid_info) };

    proc_refresh_inner(&mut pid_info, module_cache.clone()).await;

    // refresh pid info table
    tokio::spawn(async move {
        loop {
            proc_refresh_inner(&mut pid_info, module_cache.clone()).await;

            // sleep for 10 sec
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(10)) => (),
                _ = stop_rx.changed() => break,
            }
        }
    });
}

pub(crate) fn load_bpf() -> Result<Bpf> {
    #[cfg(debug_assertions)]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/debug/tail2"
    ))?;

    #[cfg(not(debug_assertions))]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/release/tail2"
    ))?;
    Ok(bpf)
}

pub(crate) async fn print_stats(bpf: &mut Bpf) -> Result<()> {
    let info: HashMap<_, u32, u64> = HashMap::try_from(bpf.map("RUN_STATS").context("no such map")?)?;
    info!("Sent: {} stacks", info.get(&(RunStatsKey::SentStackCount as u32), 0)?);
    Ok(())
}