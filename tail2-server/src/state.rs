use std::sync::{Arc, Mutex};

use rocket::tokio::sync::Notify;
use serde::Serialize;
use tail2::{calltree::frames::CallTree, dto::FrameDto, symbolication::elf::ElfCache};

pub struct CurrentCallTree {
   pub ct: Arc<Mutex<CallTree<Option<ResolvedFrame>>>>,
   pub syms: Arc<Mutex<ElfCache>>,
   pub changed: Arc<Notify>,
}

impl CurrentCallTree {
    pub fn new() -> Self {
        let ct = Arc::new(Mutex::new(CallTree::new()));
        let changed = Arc::new(Notify::new());
        let syms = Arc::new(Mutex::new(ElfCache::new()));
        Self {
            ct,
            changed,
            syms,
        }
    }
}

#[derive(Default, Clone, Eq, Serialize)]
pub struct ResolvedFrame {
    pub module_idx: usize,
    pub offset: usize,
    pub name: Option<String>,
}

impl PartialEq for ResolvedFrame {
    fn eq(&self, other: &Self) -> bool {
        self.module_idx == other.module_idx && self.name == other.name
    }
}