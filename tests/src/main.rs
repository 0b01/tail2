use std::{env::args};
use tokio::sync::mpsc;

use anyhow::Result;
use tail2::{
    client::{run::{get_pid_child, run_until_exit, RunUntil}, ws_client::ProbeState},
    Tail2, probes::{Probe, Scope},
};

#[tokio::main]
async fn main() -> Result<()> {
    let test = args().nth(1).expect("no input");
    match test.as_str() {
        "malloc" => {
            let pid = None;
            let command = Some("../tests/fixtures/aarch64/malloc".to_owned());
            let uprobe = "libc:malloc".to_owned();

            let (pid, child) = get_pid_child(pid, command);

            let (tx, mut rx) = mpsc::channel(10);
            let t2 = Tail2::new().await?;

            let probe = Probe::Uprobe {
                scope: Scope::Pid{pid: pid.unwrap()},
                uprobe,
            };
            probe.attach(&mut *t2.bpf.lock().await).unwrap();

            let probe = Probe::Perf {
                scope: Scope::Pid{pid: pid.unwrap()},
                period: 400000,
            };
            let links = probe.attach(&mut *t2.bpf.lock().await).unwrap();
            let probe_state = ProbeState::new(links);
            let cli = probe_state.cli;

            run_until_exit(t2.bpf, cli, RunUntil::ChildProcessExits(child.unwrap()), Some(tx)).await?;
            println!("{:?}", rx.recv().await.unwrap());
            println!("{:?}", rx.recv().await.unwrap());
        }
        _ => {
            panic!();
        }
    }

    Ok(())
}
