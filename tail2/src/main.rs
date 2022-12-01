#![allow(dead_code)]

use std::process::{self, exit, Command, Child};
use std::sync::Arc;

use aya::util::online_cpus;
use aya::programs::{UProbe, PerfEvent, SamplePolicy, PerfTypeId, PerfEventScope, perf_event};
use clap::Parser;
use client::{load_bpf, init_logger};
use libc::getuid;
use log::{info, error};
use nix::sys::signal::Signal::{SIGSTOP, SIGCONT};
use nix::sys::signal::kill;
use nix::unistd::Pid;
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

fn get_pid<'a>(pid: Option<u32>, command: Option<&'a String>) -> Result<Option<i32>, Child> {
    match (pid, command) {
        (None, None) => Ok(None),
        (None, Some(cmd)) => {
            info!("Launching child process: `{}`", cmd);
            match Command::new(cmd).spawn() {
                Ok(child) => {
                    let pid = child.id();
                    kill(Pid::from_raw(pid as i32), SIGSTOP).unwrap();
                    Err(child)
                }
                Err(e) => panic!("{}", e.to_string()),
            }
        },
        (Some(pid), None) => Ok(Some(pid as i32)),
        (Some(_), Some(_)) => panic!("supply one of --pid, --command")
    }
}

// TODO: use Tail2.toml for config
#[tokio::main]
async fn main() -> Result<()> {
    // bump_memlock_rlimit()?;
    let mut bpf = load_bpf()?;
    init_logger(&mut bpf).await?;

    // for awaiting Ctrl-C signal
    let (stop_tx, stop_rx) = watch::channel(());

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
            ensure_root();
            let mut bpf = load_bpf()?;
            let program: &mut PerfEvent = bpf.program_mut("capture_stack").unwrap().try_into().unwrap();
            match program.load() {
                Ok(_) => {},
                Err(e) => {
                    error!("{}", e.to_string());
                    panic!();
                }
            }

            let mut child = None;
            let pid = match get_pid(pid, command.as_ref()) {
                Err(c) => {
                    let ret = c.id() as u32;
                    child = Some(c);
                    Some(ret)
                }
                Ok(Some(pid)) => Some(pid as u32),
                Ok(None) => None
            };
            info!("{}", pid.unwrap());
            for cpu in online_cpus()? {
                let scope = match pid {
                    Some(pid) => PerfEventScope::OneProcessOneCpu { cpu, pid: pid as u32 },
                    None => PerfEventScope::AllProcessesOneCpu { cpu },
                };
                program.attach(
                    PerfTypeId::Software,
                    perf_event::perf_sw_ids::PERF_COUNT_SW_TASK_CLOCK as u64,
                    scope,
                    SamplePolicy::Period(period.unwrap_or(40_000)),
                )?;
            }

            spawn_proc_refresh(&mut bpf, stop_rx.clone(), Arc::clone(&module_cache)).await;
            let tasks = run_bpf(&mut bpf, stop_rx, module_cache)?;

            match child {
                Some(mut c) => {
                    kill(Pid::from_raw(c.id() as i32), SIGCONT).unwrap();
                    c.wait().expect("unable to execute child");
                }
                None => {
                    signal::ctrl_c().await.expect("failed to listen for event");
                }
            }

            info!("exiting");
            stop_tx.send(())?;
            for t in tasks { let _ = tokio::join!(t); }
            print_stats(&mut bpf).await?;
        },
        Commands::Uprobe { pid, uprobe, command } => {
            ensure_root();
            let mut bpf = load_bpf()?;
            let mut child = None;
            let pid = match get_pid(pid, command.as_ref()) {
                Ok(i) => i,
                Err(c) => {
                    let ret = Some(c.id() as i32);
                    child = Some(c);
                    ret
                }
            };

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
            let _uprobe_link = program.attach(Some(func), 0, src, pid).unwrap();
            info!("loaded");

            spawn_proc_refresh(&mut bpf, stop_rx.clone(), Arc::clone(&module_cache)).await;
            let tasks = run_bpf(&mut bpf, stop_rx, module_cache)?;

            match child {
                Some(mut c) => {
                    kill(Pid::from_raw(c.id() as i32), SIGCONT).unwrap();
                    c.wait().expect("unable to execute child");
                }
                None => {
                    signal::ctrl_c().await.expect("failed to listen for event");
                }
            }

            info!("exiting");
            stop_tx.send(())?;
            for t in tasks { let _ = tokio::join!(t); }
            print_stats(&mut bpf).await?;
        }
    }

    Ok(())
}
