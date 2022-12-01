use clap::{Parser, Subcommand};

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
        #[clap(long)]
        period: Option<u64>,
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
