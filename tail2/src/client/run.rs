use anyhow::Result;
use aya::maps::{AsyncPerfEventArray, HashMap, StackTraceMap};
use aya::util::online_cpus;
use bytes::BytesMut;
use tail2_common::metrics::Metrics;
use tracing::{error, info};
use nix::sys::ptrace;

use nix::unistd::{getuid, Pid};

use crate::dto::resolved_bpf_sample::ResolvedBpfSample;

use std::os::unix::prelude::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{exit, Child, Command};
use std::time::SystemTime;
use std::{mem::size_of, sync::Arc};
use tail2_common::bpf_sample::BpfSample;
use tail2_common::ConfigMapKey;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use std::time::Duration;

use anyhow::Context;
use aya::maps::MapData;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use tail2_common::procinfo::ProcInfo;
use tokio::sync::watch::Receiver;
use tokio::sync::Mutex;

use crate::processes::Processes;

use super::post_stack_client::PostStackClient;

pub(crate) async fn open_and_subcribe(
    bpf: Arc<Mutex<Bpf>>,
    tx: mpsc::Sender<BpfSample>,
    stop_rx: watch::Receiver<()>,
    ts: &mut Vec<JoinHandle<()>>,
) {
    // open bpf maps
    let mut stacks = AsyncPerfEventArray::try_from(bpf.lock().await.take_map("STACKS").unwrap()).unwrap();

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
                            // dbg!(&st.native_stack.unwind_success);

                            if tx.try_send(st).is_err() {
                                error!("slow");
                            }
                        }
                    },
                    _ = stop_rx2.changed() => {
                        tracing::info!("stopping for cpu: {cpu_id}");
                        break;
                    },
                };
            }
        });
        ts.push(t);
    }
}

pub(crate) async fn run_bpf(
    bpf: Arc<Mutex<Bpf>>,
    cli: Arc<Mutex<PostStackClient>>,
    stop_rx: watch::Receiver<()>,
    output_tx: Option<mpsc::Sender<BpfSample>>,
) -> Result<Vec<JoinHandle<()>>> {
    info!("run_bpf");
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

    let (tx, mut rx) = mpsc::channel::<BpfSample>(2048);

    let kernel_stacks =
        StackTraceMap::try_from(bpf.lock().await.take_map("KERNEL_STACKS").unwrap()).unwrap();
    let ksyms = aya::util::kernel_symbols().unwrap();

    // receiver thread
    let mut ts = vec![];
    let mut total_time = Duration::new(0, 0);
    let cli = Arc::clone(&cli);
    let t = tokio::spawn(async move {
        let mut c = 0;
        while let Some(st) = rx.recv().await {
            let start_time = SystemTime::now();

            if let Some(ref output_tx) = output_tx {
                output_tx.send(st).await.unwrap();
            }

            let st = ResolvedBpfSample::resolve(st, &kernel_stacks, &ksyms);
            if let Some(st) = st {
                let cli2 = Arc::clone(&cli);
                tokio::spawn(async move {
                    if let Err(e) = cli2.lock().await.post_stack(st).await {
                        error!("sending stack failed: {}", e.to_string());
                    }
                });
            }

            let elapsed = SystemTime::now().duration_since(start_time).unwrap();
            total_time += elapsed;
            c += 1;
        }

        let _ = cli.lock().await.flush().await;

        let avg_t = total_time / c;
        info!("Processed: {c} stacks. {avg_t:?}/st");
    });
    ts.push(t);

    open_and_subcribe(bpf, tx, stop_rx, &mut ts).await;

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

pub fn get_pid_child(
    pid: Option<u32>,
    command: Option<String>,
) -> (Option<u32>, Option<Child>) {
    match (pid, command) {
        (None, None) => (None, None),
        (None, Some(cmd)) => {
            info!("Launching child process: `{:?}`", cmd);
            let mut cmd_split = shlex::split(&cmd).unwrap().into_iter();
            let path = PathBuf::from(cmd_split.next().unwrap());
            let mut cmd = Command::new(path);
            let cmd = cmd.args(cmd_split);

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
                    (Some(pid), Some(child))
                }
                Err(e) => panic!("{}", e.to_string()),
            }
        }
        (Some(pid), None) => (Some(pid), None),
        (Some(_), Some(_)) => panic!("supply one of --pid, --command"),
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
    cli: Arc<Mutex<PostStackClient>>,
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

    spawn_proc_refresh(bpf.clone(), stop_rx.clone()).await;

    let tasks = run_bpf(bpf.clone(), cli, stop_rx, output_tx).await?;

    match run_until {
        RunUntil::CtrlC => {
            signal::ctrl_c().await.expect("failed to listen for event");
        }
        RunUntil::ChildProcessExits(mut child) => {
            info!("resuming child");
            let pid = Pid::from_raw(child.id() as i32);
            // nix::sys::wait::waitpid(pid, None).unwrap();
            ptrace::cont(pid, None).unwrap();
            child.wait().expect("unable to execute child");
            info!("child exited");
        }
        RunUntil::ExternalHalt(_) => (),
    }

    if let Some(stop_tx) = stop_tx {
        info!("exiting");
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
        dbg!(processes.processes.keys().len());
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

pub(crate) async fn print_stats(bpf: Arc<Mutex<Bpf>>) -> Result<()> {
    let bpf = &mut *bpf.lock().await;
    let info: HashMap<_, u32, u64> =
        HashMap::try_from(bpf.map("METRICS").context("no such map")?)?;
    
    info!("Sent: {} stacks", info.get(&(Metrics::SentStackCount as u32), 0).unwrap_or(0));

    for k in Metrics::iter() {
        info!("{k:?} = {}", info.get(&(k as u32), 0).unwrap_or(0));
    }

    Ok(())
}
