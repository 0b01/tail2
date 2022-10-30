use std::collections::BTreeMap;
use std::{fs, collections::HashMap};
use object::*;


#[derive(Debug)]
pub struct ElfCache {
    pub map: HashMap<String, ElfSymbols>,
}

impl ElfCache {
    pub fn build(paths: &[String]) -> Self {
        let mut map = HashMap::new();
        for path in paths {

            if map.contains_key(path) {
                continue;
            }

            if let Ok(data) = fs::read(path) {
                let kind = match object::FileKind::parse(data.as_slice()) {
                    Ok(kind) => kind,
                    Err(err) => {
                        println!("Failed to parse {path}: {err}");
                        continue;
                    }
                };

                match kind {
                    // object::FileKind::Elf32 => lookup_elf32(data),
                    object::FileKind::Elf64 => { map.insert(path.to_string(), ElfSymbols::build(&data)); },
                    _ => println!("unsupported"),
                };
            }
        }

        Self {
            map
        }
    }
}

#[derive(Debug)]
pub struct ElfSymbols {
    pub map: BTreeMap<u64, String>,
}

impl ElfSymbols {
    fn build(data: &[u8]) -> Self {
        let mut map = BTreeMap::new();
        let obj_file = object::File::parse(data).unwrap();

        for sym in obj_file.symbols().chain(obj_file.dynamic_symbols()) {
            if let Some(idx) = sym.section_index() {
                let section = obj_file.section_by_index(idx).unwrap();
                let section_name = section.name().unwrap_or("");
                if section_name == ".text" {
                    map.insert(sym.address(), sym.name().unwrap().to_owned());
                }
            }
        }

        Self {
            map,
        }
    }

    pub fn find(&self, addr: u64) -> Option<String> {
        self.map
            .range(..=addr)
            .next_back()
            .map(|(_, s)| s.clone())
    }
}
