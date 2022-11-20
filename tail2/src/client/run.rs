use anyhow::Result;
use aya::maps::{AsyncPerfEventArray, HashMap, ProgramArray};
use aya::programs::PerfEvent;
use aya::util::online_cpus;
use bytes::BytesMut;
use log::{error, info};
use tail2_common::python::{READ_PYTHON_STACK_PROG_IDX, GET_THREAD_STATE_PROG_IDX};
use tail2_common::{ConfigMapKey, Stack};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use std::{mem::size_of, sync::Arc};
use std::os::unix::prelude::MetadataExt;
use tokio::sync::{Mutex};
use std::time::{Duration, SystemTime};
use tail2::symbolication::module_cache::ModuleCache;
use tokio::sync::watch::Receiver;
use aya::Bpf;

use super::api_client::ApiStackEndpointClient;

pub(crate) fn run_bpf(bpf: &mut Bpf, stop_rx: Receiver<()>, module_cache: Arc<Mutex<ModuleCache>>) -> Result<Vec<JoinHandle<()>>> {
    // send device info
    let mut config: HashMap<_, u32, u64> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap()).unwrap();
    let stats = std::fs::metadata("/proc/self/ns/pid").unwrap();
    config.insert(ConfigMapKey::DEV as u32, stats.dev(), 0).unwrap();
    config.insert(ConfigMapKey::INO as u32, stats.ino(), 0).unwrap();

    // open bpf maps
    let mut stacks = AsyncPerfEventArray::try_from(bpf.take_map("STACKS").unwrap()).unwrap();

    let (tx, mut rx) = mpsc::channel::<Stack>(2048);

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

    // listen to bpf perf buf, send stacks to tx
    for cpu_id in online_cpus().unwrap() {
        let mut buf = stacks.open(cpu_id, Some(1024)).unwrap();
        
        let tx = tx.clone();
        let mut stop_rx2 = stop_rx.clone();
        let t = tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(size_of::<Stack>()))
                .collect::<Vec<_>>();

            loop {
                // poll for events
                tokio::select! {
                    evts = buf.read_events(&mut buffers) => {
                        let events = evts.unwrap();
                        for buf in buffers.iter_mut().take(events.read) {
                            let st = unsafe { *std::mem::transmute::<_, *const Stack>(buf.as_ptr()) };
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
    // Drop tx from main thread, so when producers join, consumer thread will also join.
    drop(tx);
    Ok(ts)
}
