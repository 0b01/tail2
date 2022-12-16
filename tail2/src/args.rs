use anyhow::Result;
use std::{process::Child};

use crate::{
    client::run::{attach_perf_event, attach_uprobe, get_pid_child, run_until_exit},
    processes::Processes,
    Tail2,
};
use clap::{Parser, Subcommand};
use log::info;

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Print Unwind table
    Table { pid: i32 },
    /// Print symbols
    Symbols { paths: Vec<String> },
    /// Print system information
    Processes {},
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
        #[clap(default_value = "400000", long)]
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
    pub async fn run(self, mut t2: Tail2) -> Result<()> {
        match self {
            Commands::Table { pid } => {
                let _ret = Processes::detect_pid(pid, &mut *t2.module_cache.lock().await);
                // dbg!(ret);
            }
            Commands::Processes {} => {
                let mut p = Processes::new(t2.module_cache);
                p.refresh().await.unwrap();
                info!("{:#?}", p);
                return Ok(());
            }
            Commands::Symbols { paths } => {
                for _p in paths {
                    // dump_elf(p)?;
                }
                return Ok(());
            }
            Commands::Sample {
                pid,
                period,
                command,
            } => {
                let mut child: Option<Child> = None;
                let pid = get_pid_child(pid, command, &mut child);

                attach_perf_event(&mut t2, pid, period).await?;
                run_until_exit(&mut t2, child, None).await?;
            }
            Commands::Uprobe {
                pid,
                uprobe,
                command,
            } => {
                let mut child: Option<Child> = None;
                let pid = get_pid_child(pid, command, &mut child);

                attach_uprobe(&mut t2, &uprobe, pid).await?;
                run_until_exit(&mut t2, child, None).await?;
            }
        }

        Ok(())
    }
}
