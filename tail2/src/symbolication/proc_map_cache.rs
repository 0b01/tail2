use std::num::NonZeroUsize;

use lru::LruCache;
use procfs::process::{MemoryMaps, Process};
use anyhow::{Context, Result};

pub struct ProcMapCache {
    pub cache: LruCache<u32, MemoryMaps>,
}

impl ProcMapCache {
    pub fn new() -> ProcMapCache {
        ProcMapCache {
            cache: LruCache::new(NonZeroUsize::new(256).unwrap()),
        }        
    }

    pub fn proc_map(&mut self, pid: u32) -> Result<MemoryMaps> {
        if self.cache.contains(&pid) {
            return Ok(self.cache.get(&pid).unwrap().clone());
        } else {
            let maps = Self::get_proc_map(pid)?;
            self.cache.put(pid, maps.clone());
            Ok(maps)
        }
    }

    pub fn refresh(&mut self, pid: u32) -> Result<MemoryMaps> {
        let maps = Self::get_proc_map(pid)?;
        self.cache.put(pid, maps.clone());
        Ok(maps)
    }

    pub fn get_proc_map(pid: u32) -> Result<MemoryMaps> {
        let proc = Process::new(pid as i32).context(format!("Failed to get process {}", pid))?;
        let maps = proc.maps().context(format!("Failed to get maps for process {}", pid))?;
        Ok(maps)
    }
}