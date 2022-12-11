use std::sync::{Arc};
use rocket::tokio::sync::Mutex;

use rocket::tokio::sync::Notify;
use serde::Serialize;
use tail2::calltree::CallTree;
use tail2::{calltree::inner::CallTreeInner, dto::FrameDto, symbolication::elf::ElfCache};

pub struct CurrentCallTree {
   pub ct: Arc<Mutex<CallTree>>,
   pub syms: Arc<Mutex<ElfCache>>,
   pub changed: Arc<Notify>,
}

impl CurrentCallTree {
    pub fn new() -> Self {
        let ct = Arc::new(Mutex::new(CallTreeInner::new()));
        let changed = Arc::new(Notify::new());
        let syms = Arc::new(Mutex::new(ElfCache::new()));
        Self {
            ct,
            changed,
            syms,
        }
    }
}