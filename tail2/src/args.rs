use anyhow::Result;

use crate::{
    client::{run::{get_pid_child, run_until_exit, RunUntil}, ws_client::ProbeState},
    processes::Processes,
    Tail2, probes::{Scope, Probe}, tail2::MOD_CACHE, symbolication::module::Module,
};
use clap::{Parser, Subcommand};
use tracing::info;

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
    pub async fn run(self, t2: Tail2) -> Result<()> {
        match self {
            Commands::Table { pid } => {
                let _ret = Processes::detect_pid(pid, &mut *MOD_CACHE.lock().await);
                // dbg!(ret);
            }
            Commands::Processes {} => {
                let mut p = Processes::new();
                p.refresh().await.unwrap();
                info!("{:#?}", p);
                return Ok(());
            }
            Commands::Symbols { paths } => {
                dbg!(&paths);
                for p in paths {
                    let module = Module::from_path(&p).unwrap();
                    println!("{:#?}", module);
                }
                return Ok(());
            }
            Commands::Sample {
                pid,
                period,
                command,
            } => {
                let (pid, child) = get_pid_child(pid, command);

                let probe = Probe::Perf{
                    scope: match pid {
                        Some(pid) => Scope::Pid {pid},
                        None => Scope::SystemWide,
                    },
                    period,
                };

                let links = probe.attach(&mut*t2.bpf.lock().await)?;
                let probe_state = ProbeState::new(probe, links);
                let run_until = child.map(RunUntil::ChildProcessExits).unwrap_or(RunUntil::CtrlC);
                run_until_exit(t2.bpf, probe_state.cli, run_until, None).await?;
            }
            Commands::Uprobe {
                pid,
                uprobe,
                command,
            } => {
                let (pid, child) = get_pid_child(pid, command);
                let probe = Probe::Uprobe{
                    scope: match pid {
                        Some(pid) => Scope::Pid{pid},
                        None => Scope::SystemWide,
                    },
                    uprobe,
                };

                let links = probe.attach(&mut *t2.bpf.lock().await)?;
                let probe_state = ProbeState::new(probe, links);
                let run_until = child.map(RunUntil::ChildProcessExits).unwrap_or(RunUntil::CtrlC);
                run_until_exit(t2.bpf, probe_state.cli, run_until, None).await?;
            }
        }

        Ok(())
    }
}
