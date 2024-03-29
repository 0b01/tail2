use std::sync::Arc;

use crate::{symbolication::module_cache::ModuleCache, tail2::CACHE};
use anyhow::Result;
use fnv::FnvHashMap;
use procfs::process::{Process, MMPermissions};
use tail2_common::procinfo::{user::ProcMapRow, ProcInfo};

#[derive(Debug)]
pub struct Processes {
    // TODO: use pid + starttime
    pub processes: FnvHashMap<i32, Box<ProcInfo>>,
}

impl Default for Processes {
    fn default() -> Self {
        Self::new()
    }
}

impl Processes {
    pub async fn refresh(&mut self) -> Result<()> {
        for prc in procfs::process::all_processes()?.flatten() {
            let module_cache = &mut *CACHE.module.lock().await;
            if let Ok(info) = Self::detect(&prc, module_cache) {
                self.processes.insert(prc.pid, info);
            }
        }

        Ok(())
    }

    pub fn new() -> Self {
        let processes = FnvHashMap::default();
        Self {
            processes,
        }
    }

    pub async fn detect_pid(pid: i32) -> Result<Box<ProcInfo>> {
        let cache = &mut *CACHE.module.lock().await;
        let process = Process::new(pid)?;
        Processes::detect(&process, cache)
    }

    /// Detects the process information from the process maps.
    /// Find executable maps and resolve them
    fn detect(process: &Process, cache: &mut ModuleCache) -> Result<Box<ProcInfo>> {
        let paths = process
            .maps()?
            .into_iter()
            .filter_map(|e| {
                if e.perms.contains(MMPermissions::EXECUTE) {
                    if let procfs::process::MMapPath::Path(p) = e.pathname {
                        let path = p.to_string_lossy().to_string();

                        let table = {
                            if let Some(ret) = cache.resolve(&path) {
                                Arc::clone(ret.unwind_table.as_ref().unwrap())
                            } else {
                                return None;
                            }
                        };

                        return Some(ProcMapRow {
                            avma: e.address.0 as usize,
                            mod_name: path,
                            unwind_table: table,
                        });
                    }
                }
                None
            })
            .collect::<Vec<_>>();

        ProcInfo::build(paths.as_slice())
    }
}
