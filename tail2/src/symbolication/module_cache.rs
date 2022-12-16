use std::{num::NonZeroUsize, sync::Arc};

use lru::LruCache;

use super::module::Module;

#[derive(Debug)]
pub struct ModuleCache(LruCache<String, Arc<Module>>);

impl Default for ModuleCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleCache {
    pub fn new() -> Self {
        Self(LruCache::new(NonZeroUsize::new(256).unwrap()))
    }

    pub fn get(&mut self, path: &str) -> Option<Arc<Module>> {
        self.0.get(path).map(Arc::clone)
    }

    pub fn resolve(&mut self, path: &str) -> Option<Arc<Module>> {
        if let ret @ Some(_) = self.get(path) {
            return ret;
        }

        let ret = Arc::new(Module::from_path(path).ok()?);
        self.0.put(path.to_string(), Arc::clone(&ret));
        Some(ret)
    }
}
