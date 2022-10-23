use std::fmt::Display;

use crate::symbolication::SymCache;

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct MyStackTrace {
    frames: Vec<(String, u64, String)>,
}

impl MyStackTrace {
    pub fn from_frames(trace: &[u64], syms: &SymCache) -> Self {
        let frames = trace.iter().map(|f| {
            if let Some(res) = syms.proc_map.lookup(*f) {
                let addr = res.address;
                let name = syms.elf_cache.map.get(&res.object_path).and_then(|c| c.find(addr)).unwrap_or("".to_owned());
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