#![allow(dead_code)]

use std::process::{self, exit, Command, Child};
use std::sync::Arc;

use aya::Bpf;
use aya::util::online_cpus;
use clap::Parser;
use tail2::symbolication::module_cache::ModuleCache;
use tokio::sync::{Mutex};
use anyhow::Result;

pub mod utils;

// TODO: use Tail2.toml for config
#[tokio::main]
async fn main() -> Result<()> {
    let module_cache = Arc::new(Mutex::new(ModuleCache::new()));

    let opt = tail2::args::Opt::parse();
    opt.command.run(module_cache).await;

    Ok(())
}

