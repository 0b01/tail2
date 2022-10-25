use std::fmt::Display;

use procfs::process::{MemoryMap, MMapPath};

use crate::{symbolication::elf::ElfCache};

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct MyStackTrace {
    frames: Vec<(String, u64, String)>,
}


impl MyStackTrace {
    pub fn from_frames(trace: &[u64], proc_map: &[MemoryMap]) -> Self {
        let paths = proc_map
            .iter()
            .filter_map(|e|to_path(&e.pathname))
            .collect::<Vec<_>>();
        let syms = ElfCache::build(&paths);
        let frames = trace.iter().map(|f| {
            if let Some((addr, res)) = lookup(proc_map, *f) {
                if let Some(path) = to_path(&res.pathname) {
                    let name = syms.map.get(&path)
                        .and_then(|c| c.find(addr))
                        .unwrap_or("".to_owned());
                    return (to_path(&res.pathname).unwrap_or("".to_string()), addr, name);
                }
            } 

            ("".to_owned(), 0, "".to_owned())
        }).collect();

        Self {
            frames,
        }
    }
}

fn to_path(path: &MMapPath) -> Option<String> {
    if let MMapPath::Path(p) = path {
        Some(p.to_str().unwrap().to_owned())
    } else {
        None
    }
}

fn lookup(proc_map: &[MemoryMap], address: u64) -> Option<(u64, &MemoryMap)> {
    for entry in proc_map.iter() {
        if address >= entry.address.0 && address < entry.address.1 {
            let translated = address - entry.address.0 + entry.offset;
            return Some((translated, &entry));
        }
    }

    None
}

impl Display for MyStackTrace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (obj, offset, name) in &self.frames {
            let _ = writeln!(f, "<{}> {}+{:#x}", name, obj, offset);
        }

        Ok(())
    }
}