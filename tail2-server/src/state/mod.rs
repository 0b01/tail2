use tail2::symbolication::elf::SymbolCache;
use tokio::sync::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

use crate::Notifiable;

pub mod notifiable;
pub mod symbolized_calltree;
pub mod agent_state;

pub use agent_state::Tail2Agent;

use self::symbolized_calltree::SymbolizedCallTree;

#[derive(Clone)]
pub struct ServerState {
    pub agents: Notifiable<Arc<Mutex<HashMap<String, Tail2Agent>>>>,
    pub symbols: Arc<Mutex<SymbolCache>>,
}

impl ServerState {
    pub fn new() -> Self {
        let symbols = Arc::new(Mutex::new(SymbolCache::new()));
        Self {
            agents: Notifiable::new(Arc::new(Mutex::new(HashMap::new()))),
            symbols,
        }
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}