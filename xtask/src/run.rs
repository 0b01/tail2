use std::{
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use anyhow::Context as _;
use clap::Parser;

use crate::build_ebpf::{build_ebpf, Architecture, Options as BuildOptions};

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    /// Build only
    #[clap(long)]
    pub build: bool,
    #[clap(long)]
    pub deploy: bool,
    /// The command used to wrap your application
    #[clap(short, long, default_value = "sudo -E")]
    pub runner: String,
    /// Arguments to pass to your application
    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,
}

/// Build the project
pub fn build(opts: &Options) -> Result<(), anyhow::Error> {
    let features = vec![
        if cfg!(target_arch = "aarch64") { "aarch64" } else if cfg!(target_arch = "x86_64") { "x86_64" } else { "" },
        if opts.deploy { "deploy" } else { "" },
    ];
    let features = features.join(" ");
    let mut args = vec![
        "+nightly",
        "build",
        "-p",
        "tail2",
        "-p",
        "tail2-server",
        // "--verbose",
        "--features",
        &features,
    ];
    if opts.release {
        args.push("--release");
    }

    dbg!(&args);

    let status = Command::new("cargo")
        .args(args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

/// Check the project
pub fn check(opts: Options) -> Result<(), anyhow::Error> {
    build_ebpf(BuildOptions {
        target: opts.bpf_target,
        release: opts.release,
    }, true).unwrap();

    Ok(())
}

pub fn run(opts: Options) -> Result<(), anyhow::Error> {
    // build our ebpf program followed by our application
    build_ebpf(BuildOptions {
        target: opts.bpf_target,
        release: opts.release,
    }, false)
    .context("Error while building eBPF program")?;
    build(&opts).context("Error while building userspace application")?;

    if opts.build {
        return Ok(());
    }

    // profile we are building (release or debug)
    let profile = if opts.release { "release" } else { "debug" };
    let client_path = format!("target/{profile}/tail2");
    let server_path = format!("target/{profile}/tail2-server");

    // arguments to pass to the application
    let mut run_args: Vec<_> = opts.run_args.iter().map(String::as_str).collect();

    // configure args
    let mut args: Vec<_> = opts.runner.trim().split_terminator(' ').collect();
    args.push(client_path.as_str());
    args.append(&mut run_args);

    let mut server_bin = Command::new(server_path).spawn()?;

    let mut client_bin = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1))
        .spawn()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    let _ = ctrlc::set_handler(move || {
        r.store(false, Ordering::Relaxed);
    });

    while running.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
    }

    server_bin.kill().expect("Failed to kill server");
    client_bin.kill().expect("Failed to kill client");

    Ok(())
}
