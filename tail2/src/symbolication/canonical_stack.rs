use std::path::PathBuf;

use procfs::process::MemoryMap;
use tail2_common::Stack;
use crate::utils::MMapPathExt;

pub struct CanonicalStack {
    pub canonical_frames: Vec<(u64, PathBuf)>,
}

pub fn convert(stack: Stack, maps: &[MemoryMap]) -> CanonicalStack {
    let len = stack.unwind_success.unwrap_or(0);
    let stack = stack.user_stack[0..len].to_vec();
    let mut canonical_frames = Vec::new();
    for f in &stack {
        if let Some((translated, map)) = lookup(maps, *f) {
            canonical_frames.push((translated, map.pathname.unwrap().to_owned()));
        }
    }

    CanonicalStack { 
        canonical_frames,
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