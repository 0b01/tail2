use rocket::tokio::sync::{Mutex, Notify};
use std::sync::Arc;

use serde::Serialize;
use tail2::calltree::CallTree;
use tail2::{calltree::inner::CallTreeInner, dto::FrameDto, symbolication::elf::ElfCache};

use crate::Notifiable;

pub mod notifiable;
pub mod agent_config;
pub use agent_config::AgentConfig;

pub struct Connections {
    pub machines: Arc<Mutex<Vec<Notifiable<AgentConfig>>>>,
}

impl Connections {
    pub fn new() -> Self {
        Self {
            machines: Arc::new(Mutex::new(vec![])),
        }
    }
}

pub struct CurrentCallTree {
    pub ct: Arc<Mutex<CallTree>>,
    pub syms: Arc<Mutex<ElfCache>>,
}

impl CurrentCallTree {
    pub fn new() -> Self {
        let ct = Arc::new(Mutex::new(CallTreeInner::new()));
        let changed = Arc::new(Notify::new());
        let syms = Arc::new(Mutex::new(ElfCache::new()));
        Self { ct, syms }
    }
}

impl Default for CurrentCallTree {
    fn default() -> Self {
        Self::new()
    }
}
