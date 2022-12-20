use std::sync::Arc;
use std::time::Duration;
use anyhow::Result;
use reqwest::Url;
use tokio::join;
use tokio::sync::{Mutex, mpsc};
use serde::{Serialize, Deserialize};
use tokio::time::sleep;
use crate::{client::run::bpf_init, symbolication::module_cache::ModuleCache};

use crate::{client::api_client::ApiStackEndpointClient, config::Tail2Config};

use futures_util::{future, pin_mut, StreamExt, SinkExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

#[derive(Serialize, Deserialize)] 
pub struct NewConnection {
    pub name: String,
}

pub struct Tail2 {
    pub bpf: aya::Bpf,
    pub config: Tail2Config,
    pub cli: Arc<Mutex<ApiStackEndpointClient>>,
    pub module_cache: Arc<Mutex<ModuleCache>>,
}

impl Tail2 {
    pub async fn new() -> Result<Self> {
        let module_cache = Arc::new(Mutex::new(ModuleCache::new()));
        let bpf = bpf_init().await?;
        let config = Tail2Config::new()?;

        let cli = Arc::new(Mutex::new(ApiStackEndpointClient::new(
            &format!("http://{}:{}", config.server.host, config.server.port),
            Arc::clone(&module_cache),
            config.server.batch_size,
        )));

        Ok(Self { bpf, config, cli, module_cache })
    }

    pub async fn run_agent(&mut self) -> Result<()> {
        let new_connection = NewConnection {
            name: "Test".to_owned(),
        };

        let payload = serde_qs::to_string(&new_connection)?;

        let connect_addr = format!("ws://{}:{}/connect?{}", self.config.server.host, self.config.server.port, payload);

        let url = Url::parse(&connect_addr).unwrap();

        let (ws_stream, _) = connect_async(url).await.expect("Failed to connect");
    
        let (mut write, read) = ws_stream.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();

        let t = tokio::spawn(read.for_each(move |message| async {
            let data = message.unwrap().into_text().unwrap();
            dbg!(data);
        }));

        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                write.send(Message::Text(msg.to_owned())).await.unwrap();
            }
        });

        loop {
            tx.send("test".to_owned()).unwrap();
            sleep(Duration::from_secs(1)).await;
        }

        t.await;
        Ok(())
    }
}