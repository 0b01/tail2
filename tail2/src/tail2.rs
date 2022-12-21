use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use anyhow::Result;
use aya::programs::perf_attach::PerfLink;
use reqwest::Url;
use tokio::join;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{Mutex, mpsc};
use serde::{Serialize, Deserialize};
use tokio::time::sleep;
use crate::client::agent_config::{AgentMessage, AgentState, NewConnection};
use crate::client::run::run_until_exit;
use crate::probes::Probe;
use crate::{client::run::bpf_init, symbolication::module_cache::ModuleCache};

use crate::{client::api_client::ApiStackEndpointClient, config::Tail2Config};

use futures_util::{future, pin_mut, StreamExt, SinkExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

pub struct Tail2 {
    pub bpf: Arc<Mutex<aya::Bpf>>,
    pub config: Tail2Config,
    pub cli: Arc<Mutex<ApiStackEndpointClient>>,
    pub module_cache: Arc<Mutex<ModuleCache>>,
    probes: Arc<Mutex<AgentState>>,
}

impl Tail2 {
    pub async fn new() -> Result<Self> {
        let module_cache = Arc::new(Mutex::new(ModuleCache::new()));
        let bpf = Arc::new(Mutex::new(bpf_init().await?));
        let config = Tail2Config::new()?;

        let cli = Arc::new(Mutex::new(ApiStackEndpointClient::new(
            &format!("http://{}:{}/stack", config.server.host, config.server.port),
            Arc::clone(&module_cache),
            config.server.batch_size,
        )));

        let probe_state = Default::default();
        Ok(Self { bpf, config, cli, module_cache, probes: probe_state })
    }

    pub async fn run_agent(&self) -> Result<()> {
        let new_connection = NewConnection {
            name: "Test".to_owned(), // TODO:
        };

        let payload = serde_qs::to_string(&new_connection)?;
        let connect_addr = format!("ws://{}:{}/connect?{}", self.config.server.host, self.config.server.port, payload);
        let url = Url::parse(&connect_addr).unwrap();

        let (ws_tx, mut ws_rx) = mpsc::unbounded_channel::<AgentMessage>();
        let (ws_stream, _) = connect_async(url).await.expect("Failed to connect");
        let (mut write, mut read) = ws_stream.split();

        let bpf = self.bpf.clone();
        let cli = self.cli.clone();
        let module_cache = self.module_cache.clone();
        let probes = self.probes.clone();
        let t = tokio::spawn(async move {
            while let Some(Ok(Message::Text(msg))) = read.next().await {
                let diff: AgentMessage = serde_json::from_str(&msg).unwrap();
                probes.clone().lock().await.on_new_msg(
                    diff,
                    ws_tx.clone(),
                    bpf.clone(),
                    cli.clone(),
                    module_cache.clone(),
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