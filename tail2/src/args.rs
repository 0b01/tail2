use std::sync::Arc;

use anyhow::Result;
use tracing::info;

use crate::{
    client::{run::{get_pid_child, run_until_exit, RunUntil}},
    processes::Processes,
    Tail2, probes::{Scope, Probe}, symbolication::{module::Module, elf::SymbolCache},
};
use clap::{Parser, Subcommand};

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
        #[clap(default_value = "4000000", long)]
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
    pub async fn run(self, t2: Tail2) -> Result<()> {
        match self {
            Commands::Table { pid } => {
                let ret = Processes::detect_pid(pid).await;
                info!("{:#?}", ret);
            }
            Commands::Processes {} => {
                let mut p = Processes::new();
                p.refresh().await.unwrap();
                tracing::info!("{:#?}", p);
                return Ok(());
            }
            Commands::Symbols { paths } => {
                let mut symbols = SymbolCache::new();
                for p in paths {
                    let module = Module::from_path(&p).unwrap();
                    println!("{module:#?}");

                    if let Some((_, e)) = symbols.entry(&p) {
                        println!("{e:#?}");
                    }
                }
                return Ok(());
            }
            Commands::Sample {
                pid,
                period,
                command,
            } => {
                let (pid, child) = get_pid_child(pid, command);

                let probe = Arc::new(Probe::Perf{
                    scope: match pid {
                        Some(pid) => Scope::Pid {pid},
                        None => Scope::SystemWide,
                    },
                    period,
                });

                let _attachment = probe.attach(&mut*t2.bpf.lock().await, &*t2.probes.lock().await).await?;
                let run_until = child.map(RunUntil::ChildProcessExits).unwrap_or(RunUntil::CtrlC);
                let clis = Arc::clone(&t2.probes.lock().await.clients);
                run_until_exit(t2.bpf, clis, run_until, None).await?;
            }
            Commands::Uprobe {
                pid,
                uprobe,
                command,
            } => {
                let (pid, child) = get_pid_child(pid, command);
                let probe = Arc::new(Probe::Uprobe{
                    scope: match pid {
                        Some(pid) => Scope::Pid{pid},
                        None => Scope::SystemWide,
                    },
                    uprobe,
                });

                let _attachment = probe.attach(&mut *t2.bpf.lock().await, &*t2.probes.lock().await).await?;
                let run_until = child.map(RunUntil::ChildProcessExits).unwrap_or(RunUntil::CtrlC);
                let clis = Arc::clone(&t2.probes.lock().await.clients);
                run_until_exit(t2.bpf, clis, run_until, None).await?;
            }
        }

        Ok(())
    }
}
