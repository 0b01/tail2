use std::{process::Child, sync::{Arc}, env::args};
use tokio::sync::{mpsc};
use tokio::sync::Mutex;

use tail2::{client::run::{bpf_init, get_pid_child, attach_uprobe, run_until_exit}, symbolication::module_cache::ModuleCache, args::Commands};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let test = args().skip(1).next().expect("no input");
    let module_cache = Arc::new(Mutex::new(ModuleCache::new()));
    match test.as_str() {
        "malloc" => {
            let pid = None;
            let command = Some("../tests/fixtures/aarch64/malloc".to_owned());
            let uprobe = "libc:malloc".to_owned();

            let mut bpf = bpf_init().await?;

            let mut child: Option<Child> = None;
            let pid = get_pid_child(pid, command, &mut child);

            let (tx, mut rx) = mpsc::channel(10);

            attach_uprobe(&mut bpf, &uprobe, pid).await?;
            run_until_exit(&mut bpf, module_cache, child, Some(tx)).await?;
            println!("{:?}", rx.recv().await.unwrap());
            println!("{:?}", rx.recv().await.unwrap());
        }
        _ => {

        }
    }

    Ok(())
}