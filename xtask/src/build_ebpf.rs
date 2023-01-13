use std::path::PathBuf;
use std::process::Command;

use clap::Parser;

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    BpfEl,
    BpfEb,
}

impl std::str::FromStr for Architecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => Architecture::BpfEl,
            "bpfeb-unknown-none" => Architecture::BpfEb,
            _ => return Err("invalid target".to_owned()),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Architecture::BpfEl => "bpfel-unknown-none",
            Architecture::BpfEb => "bpfeb-unknown-none",
        })
    }
}

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub target: Architecture,
    /// Build the release target
    #[clap(long)]
    pub release: bool,
}

pub fn build_ebpf(opts: Options) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("tail2-ebpf");
    let target = (if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        // compile_error!("unsupported target");
        ""
    })
    .to_string();
    let mut args = vec![
        // "+nightly",
        "build",
        "--features",
        target.as_str(),
        "-Z",
        "build-std=core",
        "-p",
        "tail2-ebpf",
    ];
    if opts.release {
        args.push("--release")
    }
    let status = Command::new("cargo")
        .current_dir(&dir)
        .args(&args)
        .status()
        .unwrap();
    assert!(status.success());
    Ok(())
}
