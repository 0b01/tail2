use std::{collections::HashMap, cell::RefCell, rc::Rc};

use anyhow::Result;
use procfs::process::Process;
use tail2_common::procinfo::ProcInfo;

use crate::symbolication::{module::Module, module_cache::ModuleCache};

#[derive(Debug)]
pub struct Processes {
    pub processes: HashMap<i32, Box<ProcInfo>>,
    cache: RefCell<ModuleCache>,
}

impl Processes {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
            cache: RefCell::new(ModuleCache::new()),
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

    pub fn detect_pid(pid: i32, cache: &RefCell<ModuleCache>) -> Result<Box<ProcInfo>> {
        let process = Process::new(pid)?;
        Processes::detect(&process, cache)
    }

    fn detect(process: &Process, cache: &RefCell<ModuleCache>) -> Result<Box<ProcInfo>> {

        let paths = process
            .maps()?
            .into_iter()
            .filter_map(|e| {
                if e.perms.contains('x') {
                    if let procfs::process::MMapPath::Path(p) = e.pathname {
                        let path = p.to_string_lossy().to_string();

                        let table = 
                        {
                            let mut cache = cache.borrow_mut();
                            if let Some(s) = cache.get(&path) {
                                Rc::clone(&s.unwind_table.as_ref().unwrap())
                            } else if let Some(ret) = cache.resolve(&path) {
                                Rc::clone(&ret.unwind_table.as_ref().unwrap())
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
