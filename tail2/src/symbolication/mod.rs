pub mod elf;
use crate::proc_mem::ProcMemMap;

use self::elf::ElfCache;

pub struct SymCache {
    pub proc_map: ProcMemMap,
    pub elf_cache: ElfCache,
}

impl SymCache {
    pub fn build(pid: u32) -> Self {
        let proc_map = ProcMemMap::from_process_id(pid).unwrap();
        let paths: Vec<String> = proc_map.entries.iter().map(|i| i.object_path.to_owned()).collect();
        let elf_cache = ElfCache::build(&paths);

        Self {
            proc_map,
            elf_cache,
        }
    }
}
