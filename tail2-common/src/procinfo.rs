use crate::{
    native::unwinding::aarch64::unwind_rule::UnwindRuleAarch64,
    native::unwinding::x86_64::unwind_rule::UnwindRuleX86_64, python::state::pid_data,
    runtime_type::RuntimeType,
};

/// 2 ^ 20
pub const MAX_ROWS_PER_PROC: usize = 130_000;

#[cfg(feature = "x86_64")]
type UnwindRule = UnwindRuleX86_64;
#[cfg(feature = "aarch64")]
type UnwindRule = UnwindRuleAarch64;

#[derive(Debug, Clone, Copy)]
pub struct ProcInfo {
    pub rows: [(usize, UnwindRule); MAX_ROWS_PER_PROC],
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

#[cfg(feature = "user")]
pub mod user {

    #[cfg(feature = "x86_64")]
    type UnwindTable = crate::native::unwinding::x86_64::unwind_table::UnwindTable;
    #[cfg(feature = "aarch64")]
    type UnwindTable = crate::native::unwinding::aarch64::unwind_table::UnwindTable;
    #[cfg(feature = "x86_64")]
    type UnwindTableRow = crate::native::unwinding::x86_64::unwind_table::UnwindTableRow;
    #[cfg(feature = "aarch64")]
    type UnwindTableRow = crate::native::unwinding::aarch64::unwind_table::UnwindTableRow;

    use core::{cell::RefCell, str::from_utf8_unchecked};
    use std::{
        fs::File,
        io::{BufReader, Read},
        path::{Path, PathBuf},
    };

    use super::*;
    use anyhow::{Context, Result};
    use std::sync::Arc;

    pub fn detect_runtime_type(paths: &[ProcMapRow]) -> Result<RuntimeType> {
        for path in paths {
            let base_name = Path::new(&path.mod_name)
                .file_name()
                .context("Unable to get entry file name")?
                .to_str()
                .context("unable to convert OsStr to str")?
                .to_owned();
            if base_name.starts_with("python") || base_name.starts_with("libpython") {
                return Ok(RuntimeType::python(path, &base_name, paths));
            }
        }
        Ok(RuntimeType::Unknown)
    }

    impl ProcInfo {
        /// Build a ProcInfo with a list of paths and their offsets
        /// It must be allocated on the heap or it will segfault(!)
        pub fn build(mut infos: &[ProcMapRow]) -> Result<Box<ProcInfo>> {
            let mut ret = ProcInfo::boxed();
            ret.runtime_type = detect_runtime_type(infos)?;

            // build rows
            let mut rows = Vec::new();
            for ProcMapRow {
                avma, unwind_table, ..
            } in infos
            {
                for UnwindTableRow {
                    start_address,
                    rule,
                } in &unwind_table.rows
                {
                    rows.push((*start_address + *avma, *rule));
                }
            }

            let len = rows.len().min(MAX_ROWS_PER_PROC);
            ret.rows_len = len;
            ret.rows[..len].copy_from_slice(&rows.as_slice()[..len]);
            Ok(ret)
        }
    }

    pub struct ProcMapRow {
        pub avma: usize,
        pub mod_name: String,
        pub unwind_table: Arc<UnwindTable>,
    }
}
