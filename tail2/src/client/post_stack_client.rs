use std::sync::Arc;

use crate::{
    dto::{resolved_bpf_sample::ResolvedBpfSample, stack_dto::StackBatchDto}, tail2::MOD_CACHE, config::CONFIG, probes::Probe,
};
use anyhow::Result;
use reqwest::{Client, StatusCode};

pub struct PostStackClient {
    client: Client,
    probe: Arc<Probe>,
    url: String,
    batch_size: usize,
    buf: Vec<ResolvedBpfSample>,
}

impl PostStackClient {
    pub fn new(probe: Arc<Probe>) -> Self {
        let url = format!("http://{}:{}/api/stack", CONFIG.server.host, CONFIG.server.port);
        let batch_size = CONFIG.server.batch_size.unwrap_or(1000);
        dbg!(&probe);

        Self {
            client: reqwest::Client::new(),
            probe,
            url: url.to_owned(),
            batch_size,
            buf: Vec::with_capacity(batch_size),
        }
    }

    async fn post(&self, url: &str, body: Vec<u8>) -> Result<StatusCode> {
        let res = self.client.post(url).body(body).send().await?;

        Ok(res.status())
    }

    pub async fn flush(&mut self) -> Result<StatusCode> {
        tracing::warn!("flushing post_stack_cli: {} items.", self.buf.len());
        let buf = std::mem::take(&mut self.buf);
        self.post_stacks(buf).await
    }

    pub async fn post_stack(&mut self, st: ResolvedBpfSample) -> Result<StatusCode> {
        self.buf.push(st);
        if self.buf.len() == self.batch_size {
            let stacks = std::mem::replace(&mut self.buf, Vec::with_capacity(self.batch_size));
            self.post_stacks(stacks).await?;
            self.buf.clear();
        }
        Ok(StatusCode::ACCEPTED)
    }

    async fn post_stacks(&self, stacks: Vec<ResolvedBpfSample>) -> Result<StatusCode> {
        // tracing::::info!("posting stack len {}", stacks.len());
        if stacks.is_empty() {
            return Ok(StatusCode::ACCEPTED);
        }

        let module_cache = &mut *MOD_CACHE.lock().await;
        let dto = StackBatchDto::from_stacks(self.probe.clone(), stacks, module_cache)?;
        let body = bincode::serialize(&dto).unwrap();
        self.post(&self.url, body).await
    }
}
