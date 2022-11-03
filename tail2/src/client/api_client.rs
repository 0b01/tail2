use std::sync::Arc;

use anyhow::Result;
use reqwest::{Client, StatusCode};
use tail2::{symbolication::module_cache::ModuleCache, dto::stack_dto::StackBatchDto};
use tail2_common::Stack;
use tokio::sync::Mutex;

pub struct ApiStackEndpointClient {
    client: Client,
    url: String,
    batch_size: usize,
    buf: Vec<Stack>,
    module_cache: Arc<Mutex<ModuleCache>>,
}

impl ApiStackEndpointClient {
    pub fn new(url: &str, module_cache: Arc<Mutex<ModuleCache>>, batch_size: usize) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.to_owned(),
            batch_size,
            buf: Vec::with_capacity(batch_size),
            module_cache,
        }
    }

    async fn post(&self, url: &str, body: Vec<u8>) -> Result<StatusCode> {
        let res = self.client.post(url)
            .body(body)
            .send()
            .await?;

        Ok(res.status())
    }

    pub async fn flush(&mut self) -> Result<StatusCode> {
        let buf = std::mem::replace(&mut self.buf, Vec::new());
        self.post_stacks(buf).await
    }

    pub async fn post_stack(&mut self, st: Stack) -> Result<StatusCode> {
        self.buf.push(st);
        if self.buf.len() == self.batch_size {
            let stacks = std::mem::replace(&mut self.buf, Vec::with_capacity(self.batch_size));
            self.post_stacks(stacks).await?;
        }
        Ok(StatusCode::ACCEPTED)
    }

    async fn post_stacks(&mut self, stacks: Vec<Stack>) -> Result<StatusCode> {
        if stacks.is_empty() {
            return Ok(StatusCode::ACCEPTED);
        }

        let module_cache = &mut *self.module_cache.lock().await;
        let dto = StackBatchDto::from_stacks(
            stacks,
            module_cache)?;
        drop(module_cache);
        let body = bincode::serialize(&dto).unwrap();
        self.post(&self.url, body).await
    }
}