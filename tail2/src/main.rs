#![allow(dead_code)]

use std::process::{self, exit, Command, Child};
use std::sync::Arc;

use aya::Bpf;
use aya::util::online_cpus;
use aya::programs::{UProbe, PerfEvent, SamplePolicy, PerfTypeId, PerfEventScope, perf_event};
use clap::Parser;
use tail2::client::run::{get_pid_child, attach_perf_event, run_until_exit, bpf_init, attach_uprobe};
use log::{info};
use tail2::symbolication::module_cache::ModuleCache;
use tokio::sync::{Mutex};
use anyhow::Result;

use crate::args::Commands;
use tail2::processes::Processes;

pub mod args;
pub mod utils;

// TODO: use Tail2.toml for config
#[tokio::main]
async fn main() -> Result<()> {
    let module_cache = Arc::new(Mutex::new(ModuleCache::new()));

    let opt = args::Opt::parse();
    match opt.command {
        Commands::Table {pid} => {
            let ret = Processes::detect_pid(pid, &mut *module_cache.lock().await);
            // dbg!(ret);
        }
        Commands::Processes { } => {
            let mut p = Processes::new(module_cache);
            p.refresh().await.unwrap();
            info!("{:#?}", p);
            return Ok(());
        },
        Commands::Symbols { paths } => {
            for _p in &paths {
                // dump_elf(p)?;
            }
            return Ok(());
        },
        Commands::Sample { pid , period, command} => {
            let mut bpf = bpf_init().await?;

            let mut child: Option<Child> = None;
            let pid = get_pid_child(pid, command, &mut child);

            attach_perf_event(&mut bpf, pid, period).await?;
            run_until_exit(&mut bpf, module_cache, child, None).await?;
        },
        Commands::Uprobe { pid, uprobe, command } => {
            let mut bpf = bpf_init().await?;

            let mut child: Option<Child> = None;
            let pid = get_pid_child(pid, command, &mut child);

            attach_uprobe(&mut bpf, uprobe, pid).await?;
            run_until_exit(&mut bpf, module_cache, child, None).await?;
        }
    }

    Ok(())
}

