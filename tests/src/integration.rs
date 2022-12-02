use std::{process::Child, sync::{Arc}};
use tokio::sync::{Mutex, mpsc};

use tail2::{client::run::{bpf_init, get_pid_child, attach_uprobe, run_until_exit}, symbolication::module_cache::ModuleCache};

#[tokio::test]
async fn test_malloc() {
    let module_cache = Arc::new(Mutex::new(ModuleCache::new()));
    let mut bpf = bpf_init().await.unwrap();

    let mut child: Option<Child> = None;
    let pid = get_pid_child(None, Some("../tests/fixtures/aarch64/malloc".to_owned()), &mut child);

    let (tx, mut rx) = mpsc::channel(10);
    attach_uprobe(&mut bpf, "libc:malloc".to_owned(), pid).await.unwrap();
    run_until_exit(&mut bpf, module_cache, child, Some(tx)).await.unwrap();
    rx.recv().await.unwrap();
}