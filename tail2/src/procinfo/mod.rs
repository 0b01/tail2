use std::{collections::HashMap, path::PathBuf};
use anyhow::{Result, Context};
use procfs::process::{Process, MMapPath, MemoryMap};
use tokio::runtime::Runtime;

use self::runtime_type::RuntimeType;

pub mod processes;
pub mod runtime_type;

/// Information about the runtime of a process
pub struct ProcInfo {
    /// the runtime type of the process
    pub rt: RuntimeType,
    /// memory maps
    pub maps: Vec<MemoryMap>,
}

impl std::fmt::Debug for ProcInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessInfo")
            .field("rt", &self.rt)
            .finish()
    }
}

impl ProcInfo {
    pub fn detect(process: &Process) -> Result<Self> {
        let mut rt = RuntimeType::Unknown;
        let maps = process.maps()?;
        for entry in &maps {
            if let MMapPath::Path(p) = &entry.pathname {
                let detected = RuntimeType::from(&p)?;
                if !detected.is_unknown() {
                    rt = detected;
                }
            }
        }

        Ok(Self {
            rt,
            maps,
        })
    }
}
