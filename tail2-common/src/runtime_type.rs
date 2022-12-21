use crate::python::{
    state::{pid_data, pthreads_impl},
    PythonVersion,
};

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum RuntimeType {
    Unknown,
    Python {
        pid_data: pid_data,
        is_lib: bool,
        version: PythonVersion,
    },
}

impl Default for RuntimeType {
    fn default() -> Self {
        Self::Unknown
    }
}

impl RuntimeType {
    pub fn is_unknown(&self) -> bool {
        &Self::Unknown == self
    }

    pub fn is_python(&self) -> bool {
        matches!(self, Self::Python { .. })
    }

    pub fn python_version(&self) -> PythonVersion {
        match self {
            RuntimeType::Unknown => unimplemented!(),
            RuntimeType::Python { version, .. } => *version,
        }
    }

    pub fn python_pid_data(&self) -> pid_data {
        match self {
            RuntimeType::Unknown => unimplemented!(),
            RuntimeType::Python { pid_data, .. } => *pid_data,
        }
    }

    pub fn set_python_pthreads(&mut self, new_impl: pthreads_impl) {
        match self {
            RuntimeType::Unknown => (),
            RuntimeType::Python { pid_data, .. } => {
                pid_data.pthreads_impl = new_impl;
            }
        }
    }
}

#[cfg(feature = "user")]
pub mod user {
    use anyhow::Context;
    use object::elf::{FileHeader32, FileHeader64, ProgramHeader64, PF_X, PT_LOAD};
    use object::read::elf::{ElfFile, ElfSegment, FileHeader, ProgramHeader};
    use object::Endianness;
    use object::{Endian, File, LittleEndian, Object, ObjectSegment, ObjectSymbol};

    use super::*;
    use crate::procinfo::user::ProcMapRow;
    use crate::python::state::py_globals;
    use core::str::from_utf8_unchecked;
    use std::{io::Read, path::Path};

    impl RuntimeType {
        pub fn python(row: &ProcMapRow, base_name: &str, paths: &[ProcMapRow]) -> Self {
            let is_lib = base_name.starts_with("libpython");
            let mut version = PythonVersion {
                major: 0,
                minor: 0,
                patch: 0,
            };
            if let Some(v_str) = base_name.split("python").last() {
                let mut segs = v_str.split('.');
                version.major = segs.next().unwrap().parse().unwrap();
                version.minor = segs.next().unwrap().parse().unwrap();
                // if let Ok(v) = to_python_version(&row.mod_name, v_str) {
                //     version = v;
                // }
            }

            let mut globals: py_globals = Default::default();

            // For the arbitrary constant buffer let's just use the start of the executable segment, which is
            // definitely constant.
            let py_info = PyInfo::new(&row.mod_name);
            globals.constant_buffer = row.avma + py_info.v_addr;

            // one of _PyRuntime or _PyThreadState_Current is set, depending on Python version
            if py_info._PyRuntime != 0 {
                globals._PyRuntime = row.avma + py_info._PyRuntime;
                tracing::info!("_PyRuntime: {}", globals._PyRuntime);
            } else {
                assert!(py_info._PyThreadState_Current != 0);
                globals._PyThreadState_Current = row.avma + py_info._PyThreadState_Current;
                tracing::info!("_PyThreadState_Current: {}", globals._PyThreadState_Current);
            }

            let pthreads_impl = if paths.iter().any(|i| i.mod_name.contains("musl")) {
                pthreads_impl::PTI_MUSL
            } else {
                pthreads_impl::PTI_GLIBC
            };
            RuntimeType::Python {
                is_lib,
                version,
                pid_data: pid_data {
                    pthreads_impl,
                    globals,
                    interp: 0,
                },
            }
        }
    }

    #[derive(Default, Debug)]
    struct PyInfo {
        v_addr: usize,
        _PyRuntime: usize,
        _PyThreadState_Current: usize,
    }

    impl PyInfo {
        fn new(p: &str) -> Self {
            let mut ret: PyInfo = Default::default();

            let file = std::fs::File::open(p).unwrap();
            let mmap = unsafe { memmap2::MmapOptions::new().map(&file).unwrap() };
            let elf = FileHeader64::<Endianness>::parse(&*mmap).unwrap();
            let endian = elf.endian().unwrap();
            for seg in elf.program_headers(endian, &*mmap).unwrap() {
                if seg.p_type(endian) == PT_LOAD && seg.p_flags(endian) & PF_X != 0 {
                    ret.v_addr = seg.p_vaddr(endian) as usize;
                }
            }

            let elf = object::File::parse(&*mmap).unwrap();
            for sym in elf.dynamic_symbols().chain(elf.symbols()) {
                if sym.name().unwrap_or_default() == "_PyRuntime" {
                    ret._PyRuntime = sym.address() as usize;
                }
                if sym.name().unwrap_or_default() == "_PyThreadState_Current" {
                    ret._PyThreadState_Current = sym.address() as usize;
                }
                if ret._PyRuntime > 0 && ret._PyThreadState_Current > 0 {
                    break;
                }
            }

            ret
        }
    }

    pub fn to_python_version<P: AsRef<Path>>(
        file_path: P,
        ver_str: &str,
    ) -> anyhow::Result<PythonVersion> {
        const BUFSIZ: usize = 4096;
        use std::{fs::File, io::BufReader, path::Path};

        use crate::python::PythonVersion;

        let mut rdr = BufReader::new(File::open(file_path)?);
        let mut buf = [0u8; BUFSIZ * 2];

        let mut rd1 = 0;
        loop {
            // Read
            let rd2 = rdr.read(&mut buf[rd1..(rd1 + BUFSIZ)])?;
            if rd2 != BUFSIZ {
                break;
            }

            // Search
            let to_search = &buf[..(rd1 + rd2)];
            let target = ver_str.as_bytes();
            for start in 0..to_search.len() - target.len() {
                if &to_search[start..start + target.len()] == target {
                    let mut null = None;
                    for (end, ch) in to_search[start..].iter().take(target.len()).enumerate() {
                        if *ch == 0 {
                            null = Some(end);
                            break;
                        }
                    }
                    if let Some(end) = null {
                        let ver = &to_search[start..end];
                        let mut s = ver.split(|i| *i == b'.');
                        let major = s
                            .next()
                            .map(|x| str::parse::<u8>(unsafe { from_utf8_unchecked(x) }));
                        let minor = s
                            .next()
                            .map(|x| str::parse::<u8>(unsafe { from_utf8_unchecked(x) }));
                        let patch = s
                            .next()
                            .map(|x| str::parse::<u8>(unsafe { from_utf8_unchecked(x) }));
                        if let (Some(Ok(major)), Some(Ok(minor)), Some(Ok(patch))) =
                            (major, minor, patch)
                        {
                            return Ok(PythonVersion {
                                major,
                                minor,
                                patch,
                            });
                        }
                    }
                }
            }

            // Slide
            buf.copy_within(rd1..(rd1 + rd2), 0);
            rd1 = rd2;
        }

        None.context("unable to find python version from file")
    }
}
