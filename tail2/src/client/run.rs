use anyhow::Result;
use aya::maps::{AsyncPerfEventArray, HashMap};
use aya::util::online_cpus;
use bytes::BytesMut;
use log::{error, info};
use tail2_common::stack::Stack;
use tail2_common::{ConfigMapKey, NativeStack};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use std::{mem::size_of, sync::Arc};
use std::os::unix::prelude::MetadataExt;
use tokio::sync::{Mutex};
use std::time::{Duration, SystemTime};
use tail2::symbolication::module_cache::ModuleCache;
use tokio::sync::watch;
use aya::Bpf;

use super::api_client::ApiStackEndpointClient;

pub(crate) fn open_and_subcribe(bpf: &mut Bpf, map_name: &str, tx: mpsc::Sender<Stack>, stop_rx: watch::Receiver<()>, ts: &mut Vec<JoinHandle<()>>) {
    // open bpf maps
    let mut stacks = AsyncPerfEventArray::try_from(bpf.take_map(map_name).unwrap()).unwrap();

    // listen to bpf perf buf, send stacks to tx
    for cpu_id in online_cpus().unwrap() {
        let mut buf = stacks.open(cpu_id, Some(1024)).unwrap();
        
        let tx = tx.clone();
        let mut stop_rx2 = stop_rx.clone();
        let t = tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(size_of::<NativeStack>()))
                .collect::<Vec<_>>();

            loop {
                // poll for events
                tokio::select! {
                    evts = buf.read_events(&mut buffers) => {
                        let events = evts.unwrap();
                        for buf in buffers.iter_mut().take(events.read) {
                            let st = unsafe { *std::mem::transmute::<_, *const _>(buf.as_ptr()) };
                            if tx.try_send(st).is_err() {
                                error!("slow");
                            }
                        }
                    },
                    _ = stop_rx2.changed() => {
                        break;
                    },
                };
            }
        });
        ts.push(t);
    }

}

pub(crate) fn run_bpf(bpf: &mut Bpf, stop_rx: watch::Receiver<()>, module_cache: Arc<Mutex<ModuleCache>>) -> Result<Vec<JoinHandle<()>>> {
    // send device info
    let mut config: HashMap<_, u32, u64> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap()).unwrap();
    let stats = std::fs::metadata("/proc/self/ns/pid").unwrap();
    config.insert(ConfigMapKey::DEV as u32, stats.dev(), 0).unwrap();
    config.insert(ConfigMapKey::INO as u32, stats.ino(), 0).unwrap();

    let (tx, mut rx) = mpsc::channel(2048);

    let cli = Arc::new(Mutex::new(ApiStackEndpointClient::new(
        "http://0.0.0.0:8000/stack",
        Arc::clone(&module_cache),
        400,
    )));

    // receiver thread
    let mut ts = vec![];
    let mut total_time = Duration::new(0, 0);
    let t = tokio::spawn(async move {
        let mut c = 0;
        while let Some(st) = rx.recv().await {
            let start_time = SystemTime::now();

            // dbg!(&st);

            let cli2 = Arc::clone(&cli);
            tokio::spawn(async move {
                if let Err(e) = cli2.lock().await.post_stack(st).await {
                    error!("sending stack failed: {}", e.to_string());
                }
            });

            let elapsed = SystemTime::now().duration_since(start_time).unwrap();
            total_time += elapsed;
            c += 1;
        }

        cli.lock().await.flush().await.unwrap();

        let avg_t = total_time / c;
        info!("Processed: {c} stacks. {avg_t:?}/st");
    });
    ts.push(t);

    open_and_subcribe(bpf, "STACKS", tx, stop_rx, &mut ts);

    Ok(ts)
}
