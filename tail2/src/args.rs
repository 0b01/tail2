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
        #[clap(short, long)]
        pid: Option<i32>,
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
