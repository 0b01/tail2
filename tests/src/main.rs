use std::{env::args, process::Child};
use tokio::sync::mpsc;

use anyhow::Result;
use tail2::{
    client::run::{attach_uprobe, get_pid_child, run_until_exit},
    Tail2,
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
            let mut state = Tail2::new().await?;

            attach_uprobe(&mut state, &uprobe, pid).await?;
            run_until_exit(&mut state, child, Some(tx)).await?;
            println!("{:?}", rx.recv().await.unwrap());
            println!("{:?}", rx.recv().await.unwrap());
        }
        _ => {
            panic!();
        }
    }

    Ok(())
}
