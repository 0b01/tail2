use anyhow::Result;
use clap::Parser;
use tracing::info;

pub mod utils;

// TODO: use Tail2.toml for config
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        // Configure formatting settings.
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        // Set the subscriber as the default.
        .init();

    let opt = tail2::args::Opt::parse();
    let t2 = tail2::Tail2::new().await?;
    match opt.command {
        Some(cmd) => cmd.run(t2).await.unwrap(),
        None => t2.run_agent().await?,
    }

    info!("tail2 exiting");

    Ok(())
}

