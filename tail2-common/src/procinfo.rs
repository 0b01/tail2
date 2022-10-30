use crate::runtime_type::RuntimeType;

pub const MAX_MODS_PER_PROC: usize = 128;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcMod {
    pub id: u32,
    pub avma: (u64, u64),
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcMod {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcInfo {
    pub mods: [ProcMod; MAX_MODS_PER_PROC],
    pub mods_len: usize,
    pub runtime_type: RuntimeType,
}

impl Default for ProcInfo {
    fn default() -> Self {
        Self {
            mods: [Default::default(); 128],
            mods_len: Default::default(),
            runtime_type: Default::default()
        }
    }
}

impl ProcInfo {
    /// find mod id where ip is in range
    pub fn find_mod_with_ip(&self, ip: u64) -> Option<u32> {
        self.mods
            .iter()
            .filter(|m|m.avma.0 <= ip && ip < m.avma.1)
            .map(|m| m.id)
            .next()
    }
}

#[cfg(feature = "user")]
pub mod user {
    use core::str::from_utf8_unchecked;
    use std::{path::PathBuf, io::{BufReader, Read}, fs::File};

    use crate::runtime_type::PythonVersion;
    const BUFSIZ: usize = 4096;

    use super::*;
    use anyhow::{Result, Context};
    pub fn to_python_version(file_path: &PathBuf, ver_str: &str) -> Result<PythonVersion> {
        let mut rdr = BufReader::new(File::open(file_path)?);
        let mut buf = [0u8; BUFSIZ  * 2];

        let mut rd1 = 0;
        loop {
            // Read
            let rd2 = rdr.read(&mut buf[rd1..(rd1 + BUFSIZ)])?;
            if rd2 != BUFSIZ {
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

}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcInfo {}