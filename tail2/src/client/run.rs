use anyhow::{Result, Context};
use aya::maps::{AsyncPerfEventArray, HashMap, StackTraceMap};
use aya::util::online_cpus;
use bytes::BytesMut;
use tail2_common::metrics::Metrics;
use tracing::Level;
use nix::sys::ptrace;

use nix::unistd::{getuid, Pid};

use crate::dto::resolved_bpf_sample::ResolvedBpfSample;

use std::os::unix::prelude::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{exit, Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;
use std::{mem::size_of, sync::Arc};
use tail2_common::bpf_sample::BpfSample;
use tail2_common::ConfigMapKey;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use std::time::Duration;

use aya::maps::MapData;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use tail2_common::procinfo::ProcInfo;
use tokio::sync::watch::Receiver;
use tokio::sync::Mutex;

use crate::processes::Processes;

use super::post_stack_client::PostStackClient;

pub(crate) async fn run_bpf(
    bpf: Arc<Mutex<Bpf>>,
    clis: Arc<Mutex<Vec<Arc<Mutex<PostStackClient>>>>>,
    stop_rx: watch::Receiver<()>,
    output_tx: Option<mpsc::Sender<BpfSample>>,
) -> Result<Vec<JoinHandle<()>>> {
    tracing::info!("run_bpf");
    // send device info
    {
        let bpf_ = &mut *bpf.lock().await;
        let mut config: HashMap<_, u32, u64> =
            HashMap::try_from(bpf_.map_mut("CONFIG").unwrap()).unwrap();
        let stats = std::fs::metadata("/proc/self/ns/pid").unwrap();
        config
            .insert(ConfigMapKey::DEV as u32, stats.dev(), 0)
            .unwrap();
        config
            .insert(ConfigMapKey::INO as u32, stats.ino(), 0)
            .unwrap();
    }

    let kernel_stacks =
        Arc::new(StackTraceMap::try_from(bpf.lock().await.take_map("KERNEL_STACKS").unwrap()).unwrap());

    // receiver task
    let mut ts = vec![];

    let total_time = Arc::new(AtomicU64::new(0));
    let c = Arc::new(AtomicU64::new(0));

    // open bpf maps
    let mut stacks = AsyncPerfEventArray::try_from(bpf.lock().await.take_map("STACKS").unwrap()).unwrap();

    // listen to bpf perf buf, send stacks to tx
    for cpu_id in online_cpus().unwrap() {
        let mut buf = stacks.open(cpu_id, Some(1024)).unwrap();

        let mut stop_rx2 = stop_rx.clone();
        let kernel_stacks = Arc::clone(&kernel_stacks);
        let clis = Arc::clone(&clis);
        let output_tx = output_tx.clone();
        let c = c.clone();
        let total_time = total_time.clone();
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
                            let mut st: BpfSample = unsafe { *std::mem::transmute::<_, *const _>(buf.as_ptr()) };
                            // dbg!(&st.native_stack.unwind_success);
                            st.ts_ms = SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as u64;
                            let start_time = SystemTime::now();

                            if let Some(ref output_tx) = output_tx {
                                output_tx.send(st).await.unwrap();
                            }

                            let cli = Arc::clone(&clis.lock().await[st.idx]);
                            let st = ResolvedBpfSample::resolve(st, &kernel_stacks);
                            if let Some(st) = st {
                                let cli2 = Arc::clone(&cli);
                                tokio::spawn(async move {
                                    if let Err(e) = cli2.lock().await.post_stack(st).await {
                                        tracing::error!("sending stack failed: {}", e.to_string());
                                    }
                                });
                            }

                            let elapsed = SystemTime::now().duration_since(start_time).unwrap();
                            total_time.fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
                            c.fetch_add(1, Ordering::Relaxed);
                        }
                    },
                    _ = stop_rx2.changed() => {
                        tracing::warn!("stopping for cpu: {cpu_id}");
                        tracing::warn!("processed: {}, avg: {:?}", c.load(Ordering::Relaxed), total_time.load(Ordering::Relaxed) / c.load(Ordering::Relaxed));

                        break;
                    },
                };
            }
        });
        ts.push(t);
    }
    Ok(ts)
}

/// make sure we are running with root privileges
fn ensure_root() {
    let uid = getuid().as_raw();
    if uid != 0 {
        tracing::error!("tail2 be be run with root privileges!");
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

// Get the PID of the child process to trace
// If the user did not provide a PID, then we will launch the child process
// with the command provided by the user
pub fn get_pid_child(
    pid: Option<u32>,
    command: Option<String>,
) -> (Option<u32>, Option<Child>) {
    // If no PID or command was provided, return None for both
    match (pid, command) {
        (None, None) => (None, None),
        // If no PID was provided, but a command was provided, launch the child process
        (None, Some(cmd)) => {
            // Log the command that we are launching
            tracing::info!("Launching child process: `{:?}`", cmd);
            // Split the command into a path and arguments
            let mut cmd_split = shlex::split(&cmd).unwrap().into_iter();
            let path = PathBuf::from(cmd_split.next().unwrap());
            let mut cmd = Command::new(path);
            let cmd = cmd.args(cmd_split);
            // Use ptrace to trace the child process
            unsafe {
                cmd.pre_exec(|| {
                    ptrace::traceme().or(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "ptrace TRACEME failed",
                    )))
                });
            }
            // Launch the child process
            match cmd.spawn() {
                Ok(child) => {
                    // Get the PID of the child process
                    let pid = child.id();
                    // Return the PID and the child process
                    (Some(pid), Some(child))
                }
                Err(e) => panic!("{}", e.to_string()),
            }
        }
        // If a PID was provided, but no command was provided, return the PID and None for the child process
        (Some(pid), None) => (Some(pid), None),
        // If both a PID and a command were provided, panic
        (Some(_), Some(_)) => panic!("supply one of --pid, --command"),
    }
}

pub async fn init_bpf() -> Result<Bpf> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        .with_max_level(Level::INFO)
        .init();

    ensure_root();
    bump_memlock_rlimit()?;
    let mut bpf = load_bpf()?;

    BpfLogger::init(&mut bpf).unwrap();

    Ok(bpf)
}

pub enum RunUntil {
    /// Halt on Ctrl-C
    CtrlC,
    /// Halt when child process exits
    ChildProcessExits(Child),
    /// Halt when the sender of the contained receiver sends
    ExternalHalt(Receiver<()>),
}

pub async fn run_until_exit(
    bpf: Arc<Mutex<Bpf>>,
    clis: Arc<Mutex<Vec<Arc<Mutex<PostStackClient>>>>>,
    run_until: RunUntil,
    output_tx: Option<mpsc::Sender<BpfSample>>,
) -> Result<()> {
    let (stop_tx, stop_rx) =
        if let RunUntil::ExternalHalt(rx) = &run_until {
            (None, rx.clone())
        } else {
            let (tx, rx) = watch::channel(());
            (Some(tx), rx)
        };

    spawn_proc_refresh(Arc::clone(&bpf), stop_rx.clone()).await;

    let tasks = run_bpf(Arc::clone(&bpf), clis, stop_rx, output_tx).await?;

    match run_until {
        RunUntil::CtrlC => {
            signal::ctrl_c().await.expect("failed to listen for event");
        }
        RunUntil::ChildProcessExits(mut child) => {
            tracing::info!("resuming child");
            let pid = Pid::from_raw(child.id() as i32);
            // nix::sys::wait::waitpid(pid, None).unwrap();
            ptrace::cont(pid, None).unwrap();
            child.wait().expect("unable to execute child");
            tracing::info!("child exited");
        }
        RunUntil::ExternalHalt(_) => (),
    }

    if let Some(stop_tx) = stop_tx {
        tracing::info!("exiting");
        stop_tx.send(())?;
    }

    for t in tasks {
        let _ = tokio::join!(t);
    }
    print_stats(bpf).await?;

    Ok(())
}

async fn proc_refresh_inner(
    pid_info: &mut HashMap<&mut MapData, u32, ProcInfo>,
) {
    let mut processes = Processes::new();
    if let Ok(()) = processes.refresh().await {
        tracing::warn!("# processes: {}", processes.processes.keys().len());
        // copy to maps
        for (pid, nfo) in &processes.processes {
            let nfo = nfo.as_ref();
            let _ = pid_info.insert(*pid as u32, nfo, 0);
        }
    }
}

// TODO: don't refresh, listen to mmap and execve calls
pub(crate) async fn spawn_proc_refresh(bpf: Arc<Mutex<Bpf>>, mut stop_rx: Receiver<()>) {
    let bpf = &mut *bpf.lock().await;
    let pid_info: HashMap<_, u32, ProcInfo> =
        HashMap::try_from(bpf.map_mut("PIDS").unwrap()).unwrap();
    // HACK: extend lifetime to 'static
    let mut pid_info = unsafe {
        std::mem::transmute::<
            HashMap<&mut MapData, u32, ProcInfo>,
            HashMap<&'static mut MapData, u32, ProcInfo>,
        >(pid_info)
    };

    proc_refresh_inner(&mut pid_info).await;

    // refresh pid info table
    tokio::spawn(async move {
        loop {
            proc_refresh_inner(&mut pid_info).await;

            // sleep for 10 sec
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(60)) => (),
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

pub(crate) async fn print_stats(bpf: Arc<Mutex<Bpf>>) -> Result<()> {
    let bpf = &mut *bpf.lock().await;
    let info: HashMap<_, u32, u64> =
        HashMap::try_from(bpf.map("METRICS").context("no such map")?)?;
    
    tracing::info!("Sent: {} stacks", info.get(&(Metrics::SentStackCount as u32), 0).unwrap_or(0));

    for k in Metrics::iter().split_last().unwrap().1 {
        tracing::info!("{k:?} = {}", info.get(&(*k as u32), 0).unwrap_or(0));
    }

    Ok(())
}
