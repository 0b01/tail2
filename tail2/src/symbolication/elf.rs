use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;
use indexmap::IndexMap;
use object::*;
use symbolic::demangle::demangle;

#[derive(Debug)]
pub struct ElfCache {
    pub map: IndexMap<String, Arc<ElfSymbols>>,
}

impl Default for ElfCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ElfCache {
    pub fn new() -> Self {
        Self {
            map: Default::default(),
        }
    }

    pub fn entry(&mut self, path: &str) -> Option<(usize, Arc<ElfSymbols>)> {
        if let Some((idx, _k, v)) = self.map.get_full(path) {
            Some((idx, Arc::clone(v)))
        } else {
            self.add(&[path.to_owned()]);
            self.map.get_full(path)
                .map(|(a,_k,v)|
                (a, v.clone()))
        }

    }

    pub fn add(&mut self, paths: &[String]) {
        for path in paths {

            if self.map.contains_key(path) {
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
                    object::FileKind::Elf64 => {
                        let key = path.to_string();
                        let value = Arc::new(ElfSymbols::build(&data));
                        self.map.insert(key, value); },
                    _ => println!("unsupported"),
                };
            }
        }
    }
}

#[derive(Debug)]
pub struct ElfSymbols {
    pub map: BTreeMap<usize, String>,
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
                    let name = sym.name().unwrap().to_owned();
                    let name = demangle(&name).to_string();
                    map.insert(sym.address() as usize, name);
                }
            }
        }

        Self {
            map,
        }
    }

    pub fn find(&self, addr: usize) -> Option<String> {
        self.map
            .range(..=addr)
            .next_back()
            .map(|(_, s)| s.clone())
    }
}