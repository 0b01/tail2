use std::{num::NonZeroUsize};

use lru::LruCache;
use procfs::process::Process;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub ident: String,
}

pub struct ProcessInfoCache {
    // TODO: start time + pid
    cache: LruCache<u32, ProcessInfo>,
}

impl ProcessInfoCache {
    pub fn new() -> ProcessInfoCache {
        ProcessInfoCache {
            cache: LruCache::new(NonZeroUsize::new(256).unwrap()),
        }
    }

    pub fn get(&mut self, pid: u32) -> Option<ProcessInfo> {
        if self.cache.contains(&pid) {
            Some(self.cache.get(&pid).cloned().unwrap())
        }
        else {
            self.refresh(pid)
        }
    }

    pub fn refresh(&mut self, pid: u32) -> Option<ProcessInfo> {
        let ident = Process::new(pid as i32)
            .ok()?
            .stat()
            .ok()?
            .comm;

        let value = ProcessInfo { ident };
        self.cache.put(pid, value.clone());

        Some(value)
    }
}
