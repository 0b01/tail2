#![allow(dead_code)]

use std::process::{self, exit};
use std::sync::Arc;

use aya::util::online_cpus;
use aya::programs::{UProbe, PerfEvent, SamplePolicy, PerfTypeId, PerfEventScope, perf_event};
use clap::Parser;
use client::{load_bpf, init_logger};
use libc::getuid;
use log::{info, error};
use tail2::symbolication::module_cache::{ModuleCache};
use tokio::sync::{watch, Mutex};
use tokio::signal;
use anyhow::Result;

use crate::args::Commands;
use crate::client::run::run_bpf;
use crate::client::{print_stats, spawn_proc_refresh};
use crate::processes::Processes;

pub mod args;
pub mod processes;
pub mod utils;
mod client;

/// make sure we are running with root privileges
fn ensure_root() {
    let uid = unsafe { getuid() };
    if uid != 0 {
        error!("tail2 be be run with root privileges!");
        exit(-1);
    }
}

// TODO: use Tail2.toml for config
#[tokio::main]
async fn main() -> Result<()> {
    // for awaiting Ctrl-C signal
    let (stop_tx, stop_rx) = watch::channel(());

    let module_cache = Arc::new(Mutex::new(ModuleCache::new()));

    let opt = args::Opt::parse();
    match opt.command {
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
        Commands::Py { pid , period} => {
            ensure_root();
            let mut bpf = load_bpf()?;
            init_logger(&mut bpf).await?;

            let program: &mut PerfEvent = bpf.program_mut("pyperf").unwrap().try_into().unwrap();
            if let Err(e) = program.load() {
                let s = e.to_string();
                println!("{}", s);
            }
            for cpu in online_cpus()? {
                let scope = pid
                    .map(|pid| {
                        let pid = match pid {
                            0 => process::id(),
                            _ => pid,
                        };
                        PerfEventScope::OneProcessOneCpu { cpu, pid }
                    })
                    .unwrap_or_else(|| PerfEventScope::AllProcessesOneCpu { cpu });
                program.attach(
                    PerfTypeId::Software,
                    perf_event::perf_sw_ids::PERF_COUNT_SW_TASK_CLOCK as u64,
                    scope,
                    SamplePolicy::Period(period.unwrap_or(40_000)),
                )?;
            }

            spawn_proc_refresh(&mut bpf, stop_rx.clone(), Arc::clone(&module_cache)).await;
            let tasks = run_bpf(&mut bpf, stop_rx, module_cache)?;

            signal::ctrl_c().await.expect("failed to listen for event");
            info!("exiting");
            stop_tx.send(())?;
            for t in tasks { let _ = tokio::join!(t); }
            print_stats(&mut bpf).await?;
        },
        Commands::Sample { pid , period} => {
            ensure_root();
            let mut bpf = load_bpf()?;
            init_logger(&mut bpf).await?;
            let program: &mut PerfEvent = bpf.program_mut("capture_stack").unwrap().try_into().unwrap();
            program.load().unwrap();
            for cpu in online_cpus()? {
                let scope = pid
                    .map(|pid| {
                        let pid = match pid {
                            0 => process::id(),
                            _ => pid,
                        };
                        PerfEventScope::OneProcessOneCpu { cpu, pid }
                    })
                    .unwrap_or_else(|| PerfEventScope::AllProcessesOneCpu { cpu });
                program.attach(
                    PerfTypeId::Software,
                    perf_event::perf_sw_ids::PERF_COUNT_SW_TASK_CLOCK as u64,
                    scope,
                    SamplePolicy::Period(period.unwrap_or(40_000)),
                )?;
            }

            spawn_proc_refresh(&mut bpf, stop_rx.clone(), Arc::clone(&module_cache)).await;
            let tasks = run_bpf(&mut bpf, stop_rx, module_cache)?;

            signal::ctrl_c().await.expect("failed to listen for event");
            info!("exiting");
            stop_tx.send(())?;
            for t in tasks { let _ = tokio::join!(t); }
            print_stats(&mut bpf).await?;
        },
        Commands::Alloc { pid } => {
            ensure_root();
            let mut bpf = load_bpf()?;
            init_logger(&mut bpf).await?;
            let pid = pid.map(|pid| 
                match pid {
                    0 => process::id() as i32,
                    _ => pid as i32,
                });

            let program: &mut UProbe = bpf.program_mut("malloc_enter").unwrap().try_into().unwrap();
            program.load().unwrap();
            program.attach(Some("malloc"), 0, "libc", pid).unwrap();
            info!("loaded");

            spawn_proc_refresh(&mut bpf, stop_rx.clone(), Arc::clone(&module_cache)).await;
            let tasks = run_bpf(&mut bpf, stop_rx, module_cache)?;

            signal::ctrl_c().await.expect("failed to listen for event");
            info!("exiting");
            stop_tx.send(())?;
            for t in tasks { let _ = tokio::join!(t); }
            print_stats(&mut bpf).await?;
        }
    }

    Ok(())
}
