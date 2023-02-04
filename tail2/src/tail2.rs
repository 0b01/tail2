use std::sync::Arc;

use anyhow::Result;

use aya::Bpf;
use fnv::FnvHashMap;
use once_cell::sync::Lazy;
use reqwest::Url;


use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{mpsc, watch};
use tokio::sync::Mutex;
use parking_lot::Mutex as PMutex;
use tokio::task::JoinHandle;


use crate::client::PostStackClient;
use crate::client::run::{run_until_exit, RunUntil};
use crate::client::ws_client::messages::{AgentMessage, NewConnection};


use crate::probes::Probe;
use crate::probes::probe::{ProbePool, Attachment};
use crate::{client::run::init_bpf, symbolication::module_cache::ModuleCache};

use crate::{config::Tail2Config};

use futures_util::{StreamExt, SinkExt};

use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

pub static MOD_CACHE: Lazy<Arc<PMutex<ModuleCache>>> = Lazy::new(|| 
    Arc::new(PMutex::new(ModuleCache::new()))
);

pub static HOSTNAME: Lazy<String> = Lazy::new(||
    gethostname::gethostname().to_string_lossy().to_string()
);

pub struct Probes {
    probes: FnvHashMap<Arc<Probe>, Attachment>,
    pub probe_pool: ProbePool,
    pub clients: Arc<Mutex<Vec<Arc<Mutex<PostStackClient>>>>>
}

impl Default for Probes {
    fn default() -> Self {
        Self {
            probes: FnvHashMap::default(),
            probe_pool: ProbePool::new(5),
            clients: Default::default(),
        }
    }
}

pub struct Tail2 {
    pub bpf: Arc<Mutex<aya::Bpf>>,
    pub config: Tail2Config,
    pub probes: Arc<Mutex<Probes>>,
    halt_tx: Arc<Mutex<Option<watch::Sender<()>>>>,
}

impl Tail2 {
    pub async fn new() -> Result<Self> {
        let bpf = Arc::new(Mutex::new(init_bpf().await?));
        let config = Tail2Config::new()?;

        let probe_links = Default::default();
        Ok(Self {
            bpf, config, probes: probe_links,
            halt_tx: Default::default(),
        })
    }

    pub async fn on_new_msg(
        agent_msg: AgentMessage,
        ws_tx: UnboundedSender<AgentMessage>,
        probes: Arc<Mutex<Probes>>,
        bpf: Arc<Mutex<Bpf>>,
        halt_tx: Arc<Mutex<Option<watch::Sender<()>>>>,
        join_handle: Arc<Mutex<Option<JoinHandle<Result<()>>>>>,
    ) {
        match &agent_msg {
            AgentMessage::AddProbe { probe } => {
                let probe = Arc::new(probe.to_owned());
                if probes.lock().await.probes.contains_key(&probe) {
                    ws_tx.send(AgentMessage::AgentError {
                        message: format!("Probe is already running: {probe:?}")
                    }).unwrap();
                    return;
                }

                let attachment = probe.attach(&mut *bpf.lock().await, &*probes.lock().await).await.unwrap();
                probes.lock().await.probes.insert(probe.clone(), attachment);
                tracing::info!("Probe attached: {:?}", probe);

                let clis = Arc::clone(&probes.lock().await.clients);
                if halt_tx.lock().await.is_none() {
                    let (tx, rx) = watch::channel(());
                    *halt_tx.lock().await = Some(tx);
                    let j = tokio::spawn(
                        run_until_exit(
                            Arc::clone(&bpf),
                            clis,
                            RunUntil::ExternalHalt(rx),
                            None)
                    );
                    join_handle.lock().await.replace(j);
                }

                ws_tx.send(agent_msg).unwrap();
            }
            AgentMessage::StopProbe { probe } => {
                let probe = Arc::new(probe.to_owned());
                if !probes.lock().await.probes.contains_key(&probe) {
                    ws_tx.send(AgentMessage::AgentError {
                        message: format!("Probe doesn't exist: {probe:?}")
                    }).unwrap();
                    return;
                }

                let links = probes.lock().await.probes.remove(&probe).unwrap();
                links.detach().await;

                tracing::info!("Probe detached: {:?}", &probe);
                ws_tx.send(agent_msg).unwrap();
            },
            AgentMessage::Halt => {
                if let Some(halt_tx) = &mut *halt_tx.lock().await {
                    halt_tx.send(()).unwrap();
                    ws_tx.send(AgentMessage::Halt).unwrap();
                    probes.lock().await.probes.clear();
                } else {
                    ws_tx.send(AgentMessage::AgentError {
                        message: "Unable to halt".to_string()
                    }).unwrap();
                }

                if let Some(jh) = join_handle.lock().await.take() {
                    jh.await.unwrap().unwrap();
                }
                *halt_tx.lock().await = None;
                tracing::warn!("BPF ref count: {}", Arc::strong_count(&bpf));
            }
            AgentMessage::AgentError { message: _ } => unimplemented!(),
        }
    }

    pub async fn run_agent(&self) -> Result<()> {
        let new_connection = NewConnection { hostname: HOSTNAME.to_string() };

        let payload = serde_qs::to_string(&new_connection)?;
        let connect_addr = format!("ws://{}:{}/api/connect?{}", self.config.server.host, self.config.server.port, payload);
        let url = Url::parse(&connect_addr).unwrap();

        let (ws_tx, mut ws_rx) = mpsc::unbounded_channel::<AgentMessage>();
        let (ws_stream, _) = connect_async(url).await.expect("Failed to connect");
        let (mut write, mut read) = ws_stream.split();

        tokio::spawn(async move {
            while let Some(msg) = ws_rx.recv().await {
                let s = serde_json::to_string(&msg).unwrap();
                write.send(Message::Text(s)).await.unwrap();
            }
        });

        let probes = self.probes.clone();
        let bpf  = Arc::clone(&self.bpf);
        let halt_tx = self.halt_tx.clone();
        let join_handle = Arc::new(Mutex::new(None));
        while let Some(Ok(Message::Text(msg))) = read.next().await {
            let diff: AgentMessage = serde_json::from_str(&msg).unwrap();
            Self::on_new_msg(
                diff,
                ws_tx.clone(),
                Arc::clone(&probes),
                Arc::clone(&bpf),
                Arc::clone(&halt_tx),
                Arc::clone(&join_handle),
            ).await
        }

        Ok(())
    }
}