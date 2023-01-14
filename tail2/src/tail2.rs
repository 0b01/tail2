
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

use aya::Bpf;
use once_cell::sync::Lazy;
use reqwest::Url;


use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{Mutex, mpsc, watch};
use tracing::info;


use crate::client::run::{run_until_exit, RunUntil};
use crate::client::ws_client::{ProbeState};
use crate::client::ws_client::messages::{AgentMessage, NewConnection};


use crate::probes::Probe;
use crate::{client::run::bpf_init, symbolication::module_cache::ModuleCache};

use crate::{config::Tail2Config};

use futures_util::{StreamExt, SinkExt};

use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

pub static MOD_CACHE: Lazy<Arc<Mutex<ModuleCache>>> = Lazy::new(|| 
    Arc::new(Mutex::new(ModuleCache::new()))
);

pub static HOSTNAME: Lazy<String> = Lazy::new(||
    gethostname::gethostname().to_string_lossy().to_string()
);

pub struct Tail2 {
    pub bpf: Arc<Mutex<aya::Bpf>>,
    pub config: Tail2Config,
    pub probes: Arc<Mutex<HashMap<Probe, ProbeState>>>,
    halt_tx: Arc<Mutex<Option<watch::Sender<()>>>>,
}

impl Tail2 {
    pub async fn new() -> Result<Self> {
        let bpf = Arc::new(Mutex::new(bpf_init().await?));
        let config = Tail2Config::new()?;

        let probe_links = Default::default();
        Ok(Self {
            bpf, config, probes: probe_links,
            halt_tx: Default::default(),
        })
    }

    pub async fn on_new_msg(
        diff: AgentMessage,
        tx: UnboundedSender<AgentMessage>,
        probes: Arc<Mutex<HashMap<Probe, ProbeState>>>,
        bpf: Arc<Mutex<Bpf>>,
        halt_tx: Arc<Mutex<Option<watch::Sender<()>>>>,
    ) {
        match &diff {
            AgentMessage::AddProbe { probe } => {
                if probes.lock().await.contains_key(&probe) {
                    tx.send(AgentMessage::AgentError {
                        message: format!("Probe is already running: {probe:?}")
                    }).unwrap();
                    return;
                }

                let links = probe.attach(&mut *bpf.lock().await).unwrap();
                let probe_state= ProbeState::new(probe.clone(), links);
                let cli = Arc::clone(&probe_state.cli);
                probes.lock().await.insert(probe.clone(), probe_state);
                info!("Probe attached: {:?}", probe);

                if halt_tx.lock().await.is_none() {
                    let (tx, rx) = watch::channel(());
                    *halt_tx.lock().await = Some(tx);
                    tokio::spawn(
                        run_until_exit(
                            bpf.clone(),
                            cli,
                            RunUntil::ExternalHalt(rx),
                            None)
                    );
                }

                tx.send(diff).unwrap();
            }
            AgentMessage::StopProbe { probe } => {
                if !probes.lock().await.contains_key(&probe) {
                    tx.send(AgentMessage::AgentError {
                        message: format!("Probe doesn't exist: {probe:?}")
                    }).unwrap();
                    return;
                }

                let links = probes.lock().await.remove(&probe).unwrap();
                links.detach().await;

                info!("Probe detached: {:?}", &probe);
                tx.send(diff).unwrap();
            },
            AgentMessage::Halt => {
                if let Some(halt_tx) = &mut *halt_tx.lock().await {
                    halt_tx.send(()).unwrap();
                    tx.send(AgentMessage::Halt).unwrap();
                    probes.lock().await.clear();
                } else {
                    tx.send(AgentMessage::AgentError {
                        message: "Unable to halt".to_string()
                    }).unwrap();
                }

                *halt_tx.lock().await = None;
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

        let probes = self.probes.clone();
        let bpf  = self.bpf.clone();
        let halt_tx = self.halt_tx.clone();
        let t = tokio::spawn(async move {
            while let Some(Ok(Message::Text(msg))) = read.next().await {
                let diff: AgentMessage = serde_json::from_str(&msg).unwrap();
                Self::on_new_msg(
                    diff,
                    ws_tx.clone(),
                    probes.clone(),
                    bpf.clone(),
                    halt_tx.clone(),
                ).await
            }
        });

        tokio::spawn(async move {
            while let Some(msg) = ws_rx.recv().await {
                let s = serde_json::to_string(&msg).unwrap();
                write.send(Message::Text(s)).await.unwrap();
            }
        });

        t.await.unwrap();
        Ok(())
    }
}