#![allow(dead_code)]

use anyhow::Result;
use clap::Parser;

pub mod utils;

// TODO: use Tail2.toml for config
#[tokio::main]
async fn main() -> Result<()> {
    let opt = tail2::args::Opt::parse();
    let state = tail2::Tail2::new().await?;
    opt.command.run(state).await.unwrap();

    Ok(())
}

