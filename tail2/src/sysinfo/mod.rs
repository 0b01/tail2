use std::collections::HashMap;
use anyhow::{Result, Context};
use procfs::process::{Process, MMapPath, MemoryMap};
use tokio::runtime::Runtime;

#[derive(Debug, Eq, PartialEq)]
pub enum RuntimeType {
    Unknown,
    Python {
        is_lib: bool,
        version: String,
    },
}

impl Default for RuntimeType {
    fn default() -> Self {
        Self::Unknown
    }
}

impl From<&str> for RuntimeType {
    fn from(base_name: &str) -> Self {
        if base_name.starts_with("python") || base_name.starts_with("libpython") {
            let is_lib = base_name.starts_with("libpython");
            if let Some(version) = base_name.split("python").last() {
                return Self::Python {
                    is_lib,
                    version: version.to_string(),
                };
            }
        }

        Self::Unknown
    }
}

impl RuntimeType {
    pub fn is_unknown(&self) -> bool {
        &Self::Unknown == self
    }

    pub fn is_python(&self) -> bool {
        match self {
            Self::Python { is_lib: _, version: _ } => true,
            _ => false,
        }
    }
}

/// Information about the runtime of a process
pub struct ProcessInfo {
    /// the runtime type of the process
    pub rt: RuntimeType,
    /// memory maps
    pub maps: Vec<MemoryMap>,
}

impl std::fmt::Debug for ProcessInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessInfo")
            .field("rt", &self.rt)
            .finish()
    }
}

impl ProcessInfo {
    pub fn detect(process: &Process) -> Result<Self> {
        let mut rt = RuntimeType::Unknown;
        let maps = process.maps()?;
        for entry in &maps {
            if let MMapPath::Path(p) = &entry.pathname {
                let base_name = p.file_name()
                    .context("Unable to get entry file name")?
                    .to_str().context("unable to convert OsStr to str")?;
                let detected = RuntimeType::from(base_name);
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

#[derive(Debug, Default)]
pub struct Processes {
    processes: HashMap<i32, ProcessInfo>,
}

impl Processes {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn populate(&mut self) -> Result<()> {
        for p in procfs::process::all_processes()? {
            let prc = p?;
            let pid = prc.stat()?.pid;

            if let Ok(rt) = ProcessInfo::detect(&prc) {
                self.processes.insert(pid, rt);
            }
        }

        Ok(())
    }

    /// insert a pid into the proc mapping
    pub fn entry(&mut self, pid: i32) -> Result<&ProcessInfo> {
        if self.processes.contains_key(&pid) {
            return Ok(&self.processes[&pid]);
        }

        let prc = Process::new(pid)?;
        let rt = ProcessInfo::detect(&prc)?;
        self.processes.insert(pid, rt);
        
        Ok(&self.processes[&pid])
    }
}