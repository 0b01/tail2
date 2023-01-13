use tokio::sync::Mutex;
use std::collections::HashMap;
use std::sync::Arc;


use tail2::calltree::CallTree;
use tail2::{calltree::inner::CallTreeInner, symbolication::elf::SymbolCache};

use crate::Notifiable;

pub mod notifiable;
pub mod agent_state;

pub use agent_state::Tail2Agent;

#[derive(Clone)]
pub struct ServerState {
    pub agents: Notifiable<Arc<Mutex<HashMap<String, Tail2Agent>>>>,
    pub calltree: Notifiable<Arc<SymbolizedCallTree>>,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            agents: Notifiable::new(Arc::new(Mutex::new(HashMap::new()))),
            calltree: Notifiable::new(Arc::new(SymbolizedCallTree::new())),
        }
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SymbolizedCallTree {
    pub ct: Arc<Mutex<CallTree>>,
    pub syms: Arc<Mutex<SymbolCache>>,
}

impl SymbolizedCallTree {
    pub fn new() -> Self {
        let ct = Arc::new(Mutex::new(CallTreeInner::new()));
        // let _changed = Arc::new(Notify::new());
        let syms = Arc::new(Mutex::new(SymbolCache::new()));
        Self { ct, syms }
    }
}

impl Default for SymbolizedCallTree {
    fn default() -> Self {
        Self::new()
    }
}