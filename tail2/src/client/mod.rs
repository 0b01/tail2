use std::sync::Arc;
use std::time::Duration;

use aya::maps::{HashMap, MapData};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::info;
use tail2::symbolication::module_cache::ModuleCache;
use tail2_common::procinfo::ProcInfo;
use tokio::sync::watch::Receiver;
use tokio::sync::Mutex;
use tail2_common::RunStatsKey;
use anyhow::{Result, Context};

use crate::processes::Processes;

pub mod api_client;
pub mod run;

pub(crate) async fn init_logger(bpf: &mut Bpf) -> Result<()> {
    // init logger
    let env = env_logger::Env::default()
        .filter_or("LOG_LEVEL", "info")
        .write_style_or("LOG_STYLE", "always");
    env_logger::init_from_env(env);

    BpfLogger::init(bpf).unwrap();
    Ok(())
}

// TODO: don't refresh, listen to mmap and execve calls
pub(crate) async fn spawn_proc_refresh(bpf: &mut Bpf, mut stop_rx: Receiver<()>, module_cache: Arc<Mutex<ModuleCache>>) {
    let pid_info: HashMap<_, u32, ProcInfo> = HashMap::try_from(bpf.map_mut("PIDS").unwrap()).unwrap();
    // HACK: extend lifetime to 'static
    let mut pid_info = unsafe { std::mem::transmute::<HashMap<&mut MapData, u32, ProcInfo>, HashMap<&'static mut MapData, u32, ProcInfo>>(pid_info) };

    // refresh pid info table
    tokio::spawn(async move {
        loop {
            let module_cache = Arc::clone(&module_cache);
            let mut processes = Processes::new(module_cache);
            if let Ok(()) = processes.refresh().await {
                dbg!(processes.processes.keys().len());
                // copy to maps
                for (pid, nfo) in &processes.processes {
                    let nfo = nfo.as_ref();
                    pid_info.insert(*pid as u32, nfo, 0).unwrap();
                }

                // sleep for 10 sec
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(10)) => (),
                    _ = stop_rx.changed() => break,
                }
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