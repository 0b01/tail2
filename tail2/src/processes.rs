use std::{collections::HashMap, path::PathBuf};

use anyhow::Result;
use procfs::process::{Process, MMapPath};
use tail2_common::{module::Module, procinfo::{ProcInfo, user::detect_runtime_type, ProcMod}, runtime_type::RuntimeType};

#[derive(Debug, Default)]
pub struct Processes {
    pub processes: HashMap<i32, ProcInfo>,
    pub module_map: HashMap<String, u32>,
    pub modules: Vec<Module>,
}

impl Processes {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn populate(&mut self) -> Result<()> {
        for p in procfs::process::all_processes()? {
            let prc = p?;
            let pid = prc.stat()?.pid;

            if let Ok(info) = self.detect(&prc) {
                self.processes.insert(pid, info);
            }
        }

        Ok(())
    }

    pub fn detect(&mut self, process: &Process) -> Result<ProcInfo> {
        let mut runtime_type = RuntimeType::Unknown;
        let maps = process.maps()?;
        let mut mods = vec![];
        for entry in &maps {
            if !entry.perms.contains('x') {
                continue;
            }
            if let MMapPath::Path(p) = &entry.pathname {
                if let Ok(mod_idx) = self.add_module(p) {
                    mods.push(ProcMod {
                        id: mod_idx,
                        avma: entry.address,
                    });
                    let detected = detect_runtime_type(&p)?;
                    if !detected.is_unknown() {
                        runtime_type = detected;
                        break;
                    }
                }
            }
        }

        let mut ret = ProcInfo::default();
        ret.runtime_type = runtime_type;
        ret.mods_len = mods.len();
        ret.mods[..ret.mods_len].copy_from_slice(mods.as_slice());
        Ok(ret)
    }

    pub fn add_module(&mut self, path: &PathBuf) -> Result<u32> {
        self.modules.push(Module::from_path(path)?);
        let idx = self.modules.len() - 1;
        let path = path.as_os_str().to_str().unwrap().to_owned();
        self.module_map.insert(path, idx as u32);
        Ok(idx as u32)
    }

    /// insert a pid into the proc mapping
    pub fn entry(&mut self, pid: i32) -> Result<&ProcInfo> {
        if self.processes.contains_key(&pid) {
            return Ok(&self.processes[&pid]);
        }

        let prc = Process::new(pid)?;
        let info = self.detect(&prc)?;
        self.processes.insert(pid, info);
        
        Ok(&self.processes[&pid])
    }
}
