use std::{env::args, sync::Arc};
use tokio::sync::mpsc;

use anyhow::Result;
use tail2::{
    client::{run::{get_pid_child, run_until_exit, RunUntil}},
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

            let probe = Arc::new(Probe::Uprobe {
                scope: Scope::Pid{pid: pid.unwrap()},
                uprobe,
            });
            let attachment = probe.attach(&mut *t2.bpf.lock().await, &*t2.probes.lock().await).await.unwrap();

            let clis = Arc::clone(&t2.probes.lock().await.clients);
            run_until_exit(t2.bpf, clis, RunUntil::ChildProcessExits(child.unwrap()), Some(tx)).await?;
            while let Some(e) = rx.recv().await {
                println!("{:?}", e.native_stack);
            }
        }
        _ => {
            panic!();
        }
    }

    Ok(())
}
