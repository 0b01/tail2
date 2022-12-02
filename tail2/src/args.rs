use std::{sync::Arc, process::Child};
use anyhow::Result;

use clap::{Parser, Subcommand};
use log::info;
use crate::{symbolication::module_cache::ModuleCache, client::run::{attach_uprobe, run_until_exit, get_pid_child, bpf_init, attach_perf_event}, processes::Processes};
use tokio::sync::{Mutex, mpsc};

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Print Unwind table
    Table {
        pid: i32,
    },
    /// Print symbols
    Symbols {
        paths: Vec<String>,
    },
    /// Print system information
    Processes {
    },
    /// Sample callstacks based on elapsed CPU time
    Sample {
        /// Pid to listen to, if not supplied, listen for events system wide
        /// If it's 0, listen to the tail2 agent itself
        #[clap(short, long)]
        pid: Option<u32>,
        /// launch child process with the command and attach to its pid
        #[clap(short, long)]
        command: Option<String>,
        /// sample period
        #[clap(default_value="400_000", long)]
        period: u64,
    },
    /// Attach to a userspace function, e.g. "libc:malloc"
    Uprobe {
        /// attach to pid
        #[clap(short, long)]
        pid: Option<u32>,
        /// launch child process with the command and attach to its pid
        #[clap(short, long)]
        command: Option<String>,
        /// uprobe string in the form of "module:function", e.g. "libc:malloc"
        #[clap(short, long)]
        uprobe: String,
    },
}

impl Commands {
    pub async fn run(self, module_cache: Arc<Mutex<ModuleCache>>) -> Result<()> {
        match self {
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
                for _p in paths {
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

                attach_uprobe(&mut bpf, &uprobe, pid).await?;
                run_until_exit(&mut bpf, module_cache, child, None).await?;
            }
        }

        Ok(())
    }
}