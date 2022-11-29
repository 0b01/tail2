use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use procfs::process::Process;
use tail2_common::procinfo::{ProcInfo, user::ProcMapRow};
use tail2::symbolication::module_cache::ModuleCache;
use tokio::sync::Mutex;

#[derive(Debug)]
pub struct Processes {
    // TODO: use pid + starttime
    pub processes: HashMap<i32, Box<ProcInfo>>,
    // TODO: more caching
    // pub runtime_cache: 
    module_cache: Arc<Mutex<ModuleCache>>,
}

impl Processes {
    pub async fn refresh(&mut self) -> Result<()> {
        for prc in procfs::process::all_processes()?.flatten() {
            let module_cache = &mut *self.module_cache.lock().await;
            if let Ok(info) = Self::detect(&prc, module_cache) {
                self.processes.insert(prc.pid, info);
            }
        }

        Ok(())
    }

    pub fn new(module_cache: Arc<Mutex<ModuleCache>>) -> Self {
        let processes = HashMap::new();
        Self { processes, module_cache }
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
                                Arc::clone(ret.unwind_table.as_ref().unwrap())
                            } else {
                                return None;
                            }
                        };

                        return Some(ProcMapRow {avma: e.address.0 as usize, mod_name: path, unwind_table: table});
                    }
                }
                None
            })
            .collect::<Vec<_>>();

        ProcInfo::build(paths.as_slice())
    }
}
