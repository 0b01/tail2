use std::{process::Child, sync::{Arc}, env::args};
use tokio::sync::{Mutex, mpsc};

use tail2::{client::run::{bpf_init, get_pid_child, attach_uprobe, run_until_exit}, symbolication::module_cache::ModuleCache, args::Commands};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let test = args().skip(1).next().expect("no input");
    match test.as_str() {
        "malloc" => {
            let module_cache = Arc::new(Mutex::new(ModuleCache::new()));
            let cmd = Commands::Uprobe { pid: None, command: Some("../tests/fixtures/aarch64/malloc".to_owned()), uprobe: "libc:malloc".to_owned() };
            cmd.run(module_cache).await.unwrap();
        }
        _ => {

        }
    }

    Ok(())
}