use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use procfs::process::Process;
use tail2_common::procinfo::ProcInfo;
use tail2::symbolication::module_cache::ModuleCache;

#[derive(Debug)]
pub struct Processes {
    pub processes: HashMap<i32, Box<ProcInfo>>,
}

impl Processes {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
        }
    }

    pub fn populate(&mut self, module_cache: &mut ModuleCache) -> Result<()> {
        for p in procfs::process::all_processes()? {
            if let Ok(prc) = p {
                if let Ok(info) = Self::detect(&prc, module_cache) {
                    self.processes.insert(prc.pid, info);
                }
            }
        }

        Ok(())
    }

    pub fn detect_pid(pid: i32, cache: &mut ModuleCache) -> Result<Box<ProcInfo>> {
        let process = Process::new(pid)?;
        Processes::detect(&process, cache)
    }

    fn detect(process: &Process, cache: &mut ModuleCache) -> Result<Box<ProcInfo>> {

        let paths = process
            .maps()?
            .into_iter()
            .filter_map(|e| {
                if e.perms.contains('x') {
                    if let procfs::process::MMapPath::Path(p) = e.pathname {
                        let path = p.to_string_lossy().to_string();

                        let table = 
                        {
                            if let Some(ret) = cache.resolve(&path) {
                                Arc::clone(&ret.unwind_table.as_ref().unwrap())
                            } else {
                                return None;
                            }
                        };

                        return Some((e.address.0, path, table));
                    }
                }
                None
            })
            .collect::<Vec<_>>();

        ProcInfo::build(&paths)
    }
}
