use crate::{
    runtime_type::RuntimeType,
    unwinding::aarch64::unwind_rule::UnwindRuleAarch64,
    unwinding::x86_64::unwind_rule::UnwindRuleX86_64,
};

/// 2 ^ 20
pub const MAX_ROWS_PER_PROC: usize = 130_000;

#[cfg(feature = "x86_64")]
type UnwindRule = UnwindRuleX86_64;
#[cfg(feature = "aarch64")]
type UnwindRule = UnwindRuleAarch64;

#[derive(Debug, Clone, Copy)]
pub struct ProcInfo {
    pub rows: [(u64, UnwindRule); MAX_ROWS_PER_PROC],
    pub rows_len: usize,
    pub runtime_type: RuntimeType,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcInfo {}

#[cfg(feature = "user")]
unsafe fn unsafe_allocate<T>() -> Box<T> {
    let mut grid_box: Box<T>;
    use std::alloc::{alloc, dealloc, Layout};
    let layout = Layout::new::<T>();
    let ptr = unsafe { alloc(layout) as *mut T };
    grid_box = unsafe { Box::from_raw(ptr) };
    grid_box
}

#[cfg(feature = "user")]
impl ProcInfo {
    pub fn boxed() -> Box<Self> {
        unsafe { unsafe_allocate() }
    }
}

// impl Default for ProcInfo {
//     fn default() -> Self {
//         let rows = [Default::default(); MAX_ROWS_PER_PROC];
//         ProcInfo {
//             rows,
//             rows_len: Default::default(),
//             runtime_type: Default::default()
//         }
//     }
// }

#[cfg(feature = "user")]
pub mod user {

    #[cfg(feature = "x86_64")]
    type UnwindTable = crate::unwinding::x86_64::unwind_table::UnwindTable;
    #[cfg(feature = "aarch64")]
    type UnwindRule = crate::unwinding::aarch64::unwind_table::UnwindTable;
    #[cfg(feature = "x86_64")]
    type UnwindTableRow = crate::unwinding::x86_64::unwind_table::UnwindTableRow;
    #[cfg(feature = "aarch64")]
    type UnwindRuleRow = crate::unwinding::aarch64::unwind_table::UnwindTableRow;

    use core::{str::from_utf8_unchecked, cell::RefCell};
    use std::{path::{PathBuf, Path}, io::{BufReader, Read}, fs::File};

    use crate::{runtime_type::PythonVersion};
    const BUFSIZ: usize = 4096;

    use super::*;
    use std::sync::Arc;
    use anyhow::{Result, Context};
    pub fn to_python_version<P: AsRef<Path>>(file_path: P, ver_str: &str) -> Result<PythonVersion> {
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
                    for (end, ch) in to_search[start..].iter().take(target.len()).enumerate() {
                        if *ch == 0 {
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

    pub fn detect_runtime_type<P: AsRef<Path>>(path: P) -> Result<RuntimeType> {
        let base_name = path.as_ref().file_name()
            .context("Unable to get entry file name")?
            .to_str().context("unable to convert OsStr to str")?.to_owned();
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

    impl ProcInfo {
        /// Build a ProcInfo with a list of paths and their offsets
        /// It must be allocated on the heap or it will segfault(!)
        pub fn build(mut paths: &[(u64, String, Arc<UnwindTable>)]) -> Result<Box<ProcInfo>> {
            let mut ret = ProcInfo::boxed();
            // detect rt
            for (_, path, _) in paths {
                let detected = detect_runtime_type(path)?;
                if !detected.is_unknown() {
                    ret.runtime_type = detected;
                    break;
                }
            }

            // build rows
            let mut rows = Vec::new();
            for (avma, _, table) in paths {
                for UnwindTableRow { start_address, rule } in &table.rows {
                    rows.push((start_address + avma, *rule));
                }
            }

            let len = rows.len().min(MAX_ROWS_PER_PROC);
            ret.rows_len = len;
            ret.rows[..len].copy_from_slice(&rows.as_slice()[..len]);
            Ok(ret)
        }
    }
}