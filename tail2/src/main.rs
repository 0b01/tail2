#![deny(clippy::disallowed_types)]

use anyhow::Result;
use clap::Parser;

pub mod utils;

// TODO: use Tail2.toml for config
#[tokio::main]
async fn main() -> Result<()> {
    let opt = tail2::args::Opt::parse();
    let t2 = tail2::Tail2::new().await?;
    match opt.command {
        Some(cmd) => cmd.run(t2).await.unwrap(),
        None => t2.run_agent().await?,
    }

    tracing::info!("tail2 exiting");

    Ok(())
}

