use tail2::client::agent_config::AgentConfig;
use tokio::sync::{Mutex, Notify};
use std::collections::HashMap;
use std::sync::Arc;


use tail2::calltree::CallTree;
use tail2::{calltree::inner::CallTreeInner, symbolication::elf::ElfCache};

use crate::Notifiable;

pub mod notifiable;

pub struct AppState {
    pub agents: Arc<Mutex<HashMap<String, AgentConfig>>>,
    pub calltree: Notifiable<CurrentCallTree>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            agents: Arc::new(Mutex::new(HashMap::new())),
            calltree: Notifiable::<CurrentCallTree>::new(CurrentCallTree::new()),
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
        let _changed = Arc::new(Notify::new());
        let syms = Arc::new(Mutex::new(ElfCache::new()));
        Self { ct, syms }
    }
}

impl Default for CurrentCallTree {
    fn default() -> Self {
        Self::new()
    }
}
