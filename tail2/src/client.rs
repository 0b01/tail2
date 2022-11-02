use std::mem::size_of;
use std::os::unix::prelude::MetadataExt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aya::maps::perf::{AsyncPerfEventArray};
use aya::maps::{HashMap, MapData};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::{info, error};
use tail2::symbolication::module_cache::{ModuleCache};
use tail2_common::procinfo::ProcInfo;
use tokio::sync::watch::Receiver;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tail2_common::{ConfigMapKey, Stack, InfoMapKey};
use anyhow::{Result, Context};

use crate::processes::Processes;

pub(crate) async fn init_logger(bpf: &mut Bpf) -> Result<()> {
    // init logger
    let env = env_logger::Env::default()
        .filter_or("LOG_LEVEL", "info")
        .write_style_or("LOG_STYLE", "always");
    env_logger::init_from_env(env);

    BpfLogger::init(bpf).unwrap();
    Ok(())
}

pub(crate) fn run_bpf(bpf: &mut Bpf, stop_rx: Receiver<()>, module_cache: Arc<RwLock<ModuleCache>>) -> Result<Vec<JoinHandle<()>>> {
    // send device info
    let mut config: HashMap<_, u32, u64> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap()).unwrap();
    let stats = std::fs::metadata("/proc/self/ns/pid").unwrap();
    config.insert(ConfigMapKey::DEV as u32, stats.dev(), 0).unwrap();
    config.insert(ConfigMapKey::INO as u32, stats.ino(), 0).unwrap();

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

            if let Err(e) = post_stack(st, Arc::clone(&module_cache)).await {
                error!("sending stack failed: {}", e.to_string());
            }

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

pub(crate) async fn post_stack(st: Stack, module_cache: Arc<RwLock<ModuleCache>>) -> Result<reqwest::StatusCode> {
    let st_dto = tail2::dto::StackDto::from_stack(st, &mut *module_cache.write().await)?;
    let body = bincode::serialize(&st_dto).unwrap();

    let client = reqwest::Client::new();
    let res = client.post("http://127.0.0.1:8000/stack")
        .body(body)
        .send()
        .await?;
    Ok(res.status())
}

pub(crate) async fn spawn_proc_refresh(bpf: &mut Bpf, mut stop_rx: Receiver<()>, module_cache: Arc<RwLock<ModuleCache>>) {
    let pid_info: HashMap<_, u32, ProcInfo> = HashMap::try_from(bpf.map_mut("PIDS").unwrap()).unwrap();
    // HACK: extend lifetime to 'static
    let mut pid_info = unsafe { std::mem::transmute::<HashMap<&mut MapData, u32, ProcInfo>, HashMap<&'static mut MapData, u32, ProcInfo>>(pid_info) };

    // refresh pid info table
    tokio::spawn(async move {
        loop {
            let mut p = Processes::new();
            let _ = p.populate(&mut *module_cache.write().await);

            dbg!(p.processes.keys().len());
            // copy to maps
            for (pid, nfo) in &p.processes {
                let nfo = nfo.as_ref();
                let _ = pid_info.insert(*pid as u32, nfo, 0);
            }

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
        "../../target/bpfel-unknown-none/debug/tail2"
    ))?;

    #[cfg(not(debug_assertions))]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tail2"
    ))?;
    Ok(bpf)
}

pub(crate) async fn print_stats(bpf: &mut Bpf) -> Result<()> {
    let info: HashMap<_, u32, u64> = HashMap::try_from(bpf.map("RUN_INFO").context("no such map")?)?;
    info!("Sent: {} stacks", info.get(&(InfoMapKey::SentStackCount as u32), 0)?);
    Ok(())
}