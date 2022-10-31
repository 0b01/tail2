use std::{collections::HashMap};

use anyhow::{Result};
use procfs::process::Process;
use tail2_common::procinfo::ProcInfo;

#[derive(Debug, Default)]
pub struct Processes {
    pub processes: HashMap<i32, Box<ProcInfo>>,
}

impl Processes {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
        }
    }

    pub fn populate(&mut self) -> Result<()> {
        for p in procfs::process::all_processes()? {
            if let Ok(prc) = p {
                let pid = prc.stat()?.pid;
                if let Ok(info) = self.detect(&prc) {
                    self.processes.insert(pid, info);
                }
            }
        }

        Ok(())
    }

    pub fn detect(&mut self, process: &Process) -> Result<Box<ProcInfo>> {
        let paths = process
            .maps()?
            .into_iter()
            .filter_map(|e| {
                if e.perms.contains('x') {
                    if let procfs::process::MMapPath::Path(p) = e.pathname {
                        return Some((e.address.0, p));
                    }
                }
                None
            })
            .collect::<Vec<_>>();

        ProcInfo::build(&paths)
    }
}
