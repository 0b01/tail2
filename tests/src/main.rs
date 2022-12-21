use std::{env::args, process::Child};
use tokio::sync::mpsc;

use anyhow::Result;
use tail2::{
    client::{run::{get_pid_child, run_until_exit}},
    Tail2, probes::{Probe, UprobeProbe, Scope},
};

#[tokio::main]
async fn main() -> Result<()> {
    let test = args().nth(1).expect("no input");
    match test.as_str() {
        "malloc" => {
            let pid = None;
            let command = Some("../tests/fixtures/aarch64/malloc".to_owned());
            let uprobe = "libc:malloc".to_owned();

            let mut child: Option<Child> = None;
            let pid = get_pid_child(pid, command, &mut child);

            let (tx, mut rx) = mpsc::channel(10);
            let state = Tail2::new().await?;

            let probe = Probe::Uprobe(UprobeProbe {
                scope: match pid {
                    Some(pid) => Scope::Pid(pid),
                    None => Scope::SystemWide,
                },
                uprobe,
            });
            probe.attach(&mut *state.bpf.lock().await).unwrap();
            // attach_uprobe(&mut state, &uprobe, pid).await?;
            run_until_exit(state.bpf, state.cli, state.module_cache, child, Some(tx)).await?;
            println!("{:?}", rx.recv().await.unwrap());
            println!("{:?}", rx.recv().await.unwrap());
        }
        _ => {
            panic!();
        }
    }

    Ok(())
}
