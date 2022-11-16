use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Print symbols
    Symbols {
        paths: Vec<String>,
    },
    /// Sample
    Sample {
        /// Pid to listen to, if not supplied, listen for events system wide
        /// If it's 0, listen to the tail2 agent itself
        #[clap(short, long)]
        pid: Option<u32>,
        #[clap(long)]
        period: Option<u64>,
    },
    /// Listen to alloc events
    Alloc {
        #[clap(short, long)]
        pid: Option<i32>,
    },
    /// Print system information
    Processes {
    },
}
