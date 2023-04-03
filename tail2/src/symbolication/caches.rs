use std::sync::Arc;

use tokio::sync::Mutex;

use super::{module_cache::ModuleCache, proc_map_cache::ProcMapCache, process_info_cache::ProcessInfoCache};

pub struct Cache {
    pub module: Arc<Mutex<ModuleCache>>,
    pub proc_map: Arc<Mutex<ProcMapCache>>,
    pub process_info: Arc<Mutex<ProcessInfoCache>>,
}

impl Cache {
    pub fn new() -> Cache {
        Cache {
            module: Arc::new(Mutex::new(ModuleCache::new())),
            proc_map: Arc::new(Mutex::new(ProcMapCache::new())),
            process_info: Arc::new(Mutex::new(ProcessInfoCache::new())),
        }
    }
}