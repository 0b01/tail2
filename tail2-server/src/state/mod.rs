use fnv::FnvHashMap;
use tail2::symbolication::elf::SymbolCache;
use tail2_db::manager::Manager;
use tokio::sync::Mutex;
use std::sync::Arc;
use crate::Notifiable;
pub mod notifiable;
pub mod symbolized_calltree;
pub mod agent_state;
pub use agent_state::Tail2Agent;

#[derive(Clone)]
pub struct ServerState {
    pub agents: Notifiable<FnvHashMap<String, Tail2Agent>>,
    pub symbols: Arc<Mutex<SymbolCache>>,
    pub manager: Arc<Mutex<Manager>>,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            agents: Notifiable::new(FnvHashMap::default()),
            symbols: Arc::new(Mutex::new(SymbolCache::new())),
            manager: Arc::new(Mutex::new(Manager::new("./db"))),
        }
    }

    pub async fn shutdown(&self) {
        self.manager.lock().await.clear();
        self.agents.lock().await.clear();
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}