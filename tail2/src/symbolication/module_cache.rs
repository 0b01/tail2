use std::{rc::Rc, num::NonZeroUsize};

use lru::LruCache;

use super::module::Module;

#[derive(Debug)]
pub struct ModuleCache(LruCache<String, Rc<Module>>);

impl ModuleCache {
    pub fn new() -> Self {
        Self(LruCache::new(NonZeroUsize::new(256).unwrap()))
    }

    pub fn get(&mut self, path: &str) -> Option<Rc<Module>> {
        self.0.get(path).map(Rc::clone)
    }

    pub fn resolve(&mut self, path: &str) -> Option<Rc<Module>> {
        let ret = Rc::new(Module::from_path(&path).ok()?);
        self.0.put(path.to_string(), Rc::clone(&ret));
        Some(ret)
    }
}