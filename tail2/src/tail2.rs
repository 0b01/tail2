use std::sync::Arc;

use anyhow::Result;
use reqwest_eventsource::{EventSource, Event};
use rocket::futures::StreamExt;
use crate::{client::run::bpf_init, symbolication::module_cache::ModuleCache};
use tokio::sync::Mutex;

use crate::{client::api_client::ApiStackEndpointClient, config::Tail2Config};

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
            &config.server.url,
            Arc::clone(&module_cache),
            config.server.batch_size,
        )));

        Ok(Self { bpf, config, cli, module_cache })
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut es = EventSource::get(&format!("{}/connect", self.config.server.url));
        while let Some(event) = es.next().await {
            match event {
                Ok(Event::Open) => println!("Connection Open!"),
                Ok(Event::Message(message)) => println!("Message: {:#?}", message),
                Err(err) => {
                    println!("Error: {}", err);
                    es.close();
                }
            }
        }

        Ok(())
    }
}