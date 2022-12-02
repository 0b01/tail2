use std::process::Command;

use clap::Parser;
use anyhow::Result;

#[derive(Debug, Parser)]
pub struct Options {
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
}

pub fn test(opts: Options) -> Result<()> {
    let mut args = vec![
        "+nightly",
        "test",
    ];
    if opts.release {
        args.push("--release")
    }
    args.push("--");
    args.push("--nocapture");
    let status = Command::new("cargo")
        .env("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER", "sudo -E")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}