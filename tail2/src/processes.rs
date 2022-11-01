use std::{collections::HashMap, cell::RefCell, num::NonZeroUsize};

use anyhow::{Result};
use lru::LruCache;
use procfs::process::{Process};
use tail2_common::{procinfo::{ProcInfo, user::UnwindTableCache}};

#[derive(Debug)]
pub struct Processes {
    pub processes: HashMap<i32, Box<ProcInfo>>,
    cache: UnwindTableCache,
}

impl Processes {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
            cache: RefCell::new(LruCache::new(NonZeroUsize::new(256).unwrap())),
        }
    }

    pub fn populate(&mut self) -> Result<()> {
        for p in procfs::process::all_processes()? {
            if let Ok(prc) = p {
                if let Ok(info) = Self::detect(&prc, &self.cache) {
                    self.processes.insert(prc.pid, info);
                }
            }
        }

        Ok(())
    }

    pub fn detect_pid(pid: i32, cache: &UnwindTableCache) -> Result<Box<ProcInfo>> {
        let process = Process::new(pid)?;
        Processes::detect(&process, cache)
    }

    fn detect(process: &Process, cache: &UnwindTableCache) -> Result<Box<ProcInfo>> {
        let paths = process
            .maps()?
            .into_iter()
            .filter_map(|e| {
                if e.perms.contains('x') {
                    if let procfs::process::MMapPath::Path(p) = e.pathname {
                        return Some((e.address.0, p.to_string_lossy().to_string()));
                    }
                }
                None
            })
            .collect::<Vec<_>>();

        ProcInfo::build(&paths, cache)
    }
}
