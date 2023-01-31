use std::process::Command;

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
}

pub fn test(opts: Options) -> Result<()> {
    let mut args = vec![
        "test",
        "--features",
        if cfg!(target_arch = "aarch64") { "aarch64" } else if cfg!(target_arch = "x86_64") { "x86_64" } else { "" },
    ];
    if opts.release {
        args.push("--release")
    }
    args.push("--");
    args.push("--nocapture");
    let status = Command::new("cargo")
        .env("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER", "sudo -E")
        .env("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER", "sudo -E")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}
