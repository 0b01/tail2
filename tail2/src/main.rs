use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use log::info;
use tail2::Tail2;
use tokio::sync::Mutex;

pub mod utils;

// TODO: use Tail2.toml for config
#[tokio::main]
async fn main() -> Result<()> {
    let opt = tail2::args::Opt::parse();
    let mut t2 = tail2::Tail2::new().await?;
    match opt.command {
        Some(cmd) => cmd.run(t2).await.unwrap(),
        None => Tail2::run_agent(Arc::new(Mutex::new(t2))).await?,
    }

    info!("tail2 exiting");

    Ok(())
}

