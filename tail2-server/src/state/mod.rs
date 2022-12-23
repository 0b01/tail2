use tokio::sync::{Mutex, Notify};
use std::collections::HashMap;
use std::sync::Arc;


use tail2::calltree::CallTree;
use tail2::{calltree::inner::CallTreeInner, symbolication::elf::ElfCache};

use crate::Notifiable;

pub mod notifiable;
pub mod agent_state;

pub use agent_state::Tail2Agent;

pub struct ServerState {
    pub agents: Arc<Mutex<HashMap<String, Tail2Agent>>>,
    pub agents_changed: Arc<Notify>,
    pub calltree: Notifiable<CurrentCallTree>,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            agents: Arc::new(Mutex::new(HashMap::new())),
            agents_changed: Arc::new(Notify::new()),
            calltree: Notifiable::<CurrentCallTree>::new(CurrentCallTree::new()),
        }
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
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