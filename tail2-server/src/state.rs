use std::sync::{Arc};
use rocket::tokio::sync::Mutex;

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

#[derive(Clone, Eq, PartialEq, Serialize, Debug)]
pub enum CodeType {
    Native = 0,
    Python = 1,
    Kernel = 2,
}

#[derive(Clone, Eq, Serialize, Debug)]
pub struct ResolvedFrame {
    pub module_idx: usize,
    pub offset: usize,
    pub code_type: CodeType,
    pub name: Option<String>,
}

impl PartialEq for ResolvedFrame {
    fn eq(&self, other: &Self) -> bool {
        self.module_idx == other.module_idx && self.name == other.name
    }
}