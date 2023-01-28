mod build_ebpf;
mod run;
mod test;

use std::process::exit;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    BuildEbpf(build_ebpf::Options),
    Check(run::Options),
    Run(run::Options),
    Test(test::Options),
}

fn main() {
    let opts = Options::parse();

    use Command::*;
    let ret = match opts.command {
        BuildEbpf(opts) => build_ebpf::build_ebpf(opts, false),
        Check(opts) => run::check(opts),
        Run(opts) => run::run(opts),
        Test(opts) => test::test(opts),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
