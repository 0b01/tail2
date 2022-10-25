use std::collections::HashMap;

use anyhow::Result;
use procfs::process::Process;

use super::ProcInfo;

#[derive(Debug, Default)]
pub struct Processes {
    processes: HashMap<i32, ProcInfo>,
}

impl Processes {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn populate(&mut self) -> Result<()> {
        for p in procfs::process::all_processes()? {
            let prc = p?;
            let pid = prc.stat()?.pid;

            if let Ok(info) = ProcInfo::detect(&prc) {
                self.processes.insert(pid, info);
            }
        }

        Ok(())
    }

    /// insert a pid into the proc mapping
    pub fn entry(&mut self, pid: i32) -> Result<&ProcInfo> {
        if self.processes.contains_key(&pid) {
            return Ok(&self.processes[&pid]);
        }

        let prc = Process::new(pid)?;
        let info = ProcInfo::detect(&prc)?;
        self.processes.insert(pid, info);
        
        Ok(&self.processes[&pid])
    }
}