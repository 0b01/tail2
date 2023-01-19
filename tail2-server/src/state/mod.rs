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
    pub calltree: Notifiable<Arc<Mutex<SymbolizedCallTree>>>,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            agents: Notifiable::new(Arc::new(Mutex::new(HashMap::new()))),
            calltree: Notifiable::new(Arc::new(Mutex::new(SymbolizedCallTree::new()))),
        }
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}