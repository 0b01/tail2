use std::fmt::Display;

use crate::{symbolication::elf::ElfCache, unwinding::proc_mem::ProcMemMap};

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct MyStackTrace {
    frames: Vec<(String, u64, String)>,
}

impl MyStackTrace {
    pub fn from_frames(trace: &[u64], proc_map: &ProcMemMap) -> Self {
        let paths = proc_map.entries.iter().map(|e|e.object_path.to_owned()).collect::<Vec<_>>();
        let syms = ElfCache::build(&paths);
        let frames = trace.iter().map(|f| {
            if let Some(res) = proc_map.lookup(*f) {
                let addr = res.address;
                let name = syms.map.get(&res.object_path)
                    .and_then(|c| c.find(addr))
                    .unwrap_or("".to_owned());
                (res.object_path, addr, name)
            } else {
                ("".to_owned(), 0, "".to_owned())
            }
        }).collect();

        Self {
            frames,
        }
    }
}

impl Display for MyStackTrace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (obj, offset, name) in &self.frames {
            let _ = writeln!(f, "<{}> {}+{:#x}", name, obj, offset);
        }

        Ok(())
    }
}