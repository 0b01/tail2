use std::{collections::{HashMap, HashSet}, path::PathBuf, fs::File, io::{BufReader, Read, BufRead}, str::{from_utf8, from_utf8_unchecked}};
use anyhow::{Result, Context};
use libc::BUFSIZ;
use procfs::process::{Process, MMapPath, MemoryMap};
use tail2_common::runtime_type::{RuntimeType, PythonVersion};
use tokio::runtime::Runtime;

pub mod processes;

pub fn to_python_version(file_path: &PathBuf, ver_str: &str) -> Result<PythonVersion> {
    let mut rdr = BufReader::new(File::open(file_path)?);
    let mut buf = [0u8; BUFSIZ as usize * 2];

    let mut rd1 = 0;
    loop {
        // Read
        let rd2 = rdr.read(&mut buf[rd1..(rd1 + BUFSIZ as usize)])?;
        if rd2 != BUFSIZ as usize {
            break;
        }

        // Search
        let to_search = &buf[..(rd1+rd2)];
        let target = ver_str.as_bytes();
        for start in 0..to_search.len()-target.len() {
            if &to_search[start..start+target.len()] == target {
                let mut null = None;
                for end in start+target.len()..to_search.len() {
                    if to_search[end] == 0 {
                        null = Some(end);
                        break;
                    }
                }
                if let Some(end) = null {
                    let ver = &to_search[start..end];
                    let mut s = ver.split(|i|*i == b'.');
                    let major = s.next().map(|x|str::parse::<u8>(unsafe{from_utf8_unchecked(x)}));
                    let minor = s.next().map(|x|str::parse::<u8>(unsafe{from_utf8_unchecked(x)}));
                    let patch = s.next().map(|x|str::parse::<u8>(unsafe{from_utf8_unchecked(x)}));
                    if let (Some(Ok(major)), Some(Ok(minor)), Some(Ok(patch))) = (major, minor, patch) {
                        return Ok(PythonVersion { major, minor, patch });
                    }
                }
            }
        }
        
        // Slide
        buf.copy_within(rd1..(rd1+rd2), 0);
        rd1 = rd2;
    }

    None.context("unable to find python version from file")
}

pub fn detect_runtime_type(path: &PathBuf) -> Result<RuntimeType> {
    let base_name = path.file_name()
        .context("Unable to get entry file name")?
        .to_str().context("unable to convert OsStr to str")?;
    if base_name.starts_with("python") || base_name.starts_with("libpython") {
        let is_lib = base_name.starts_with("libpython");
        if let Some(version) = base_name.split("python").last() {
            if let Ok(version) = to_python_version(path, version) {
                return Ok(RuntimeType::Python {
                    is_lib,
                    version,
                });
            }
        }
    }

    Ok(RuntimeType::Unknown)
}

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
        let mut maps = process.maps()?;
        for entry in &maps {
            if let MMapPath::Path(p) = &entry.pathname {
                let detected = detect_runtime_type(&p)?;
                if !detected.is_unknown() {
                    rt = detected;
                    break;
                }
            }
        }

        Ok(Self {
            rt,
            maps,
        })
    }
}
