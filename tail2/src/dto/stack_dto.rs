use std::sync::Arc;

use anyhow::{Context, Result};
use procfs::process::MemoryMap;
use serde::{Deserialize, Serialize};
use tail2_common::{NativeStack, pidtgid::PidTgid};

use crate::{
    symbolication::{module::Module, module_cache::ModuleCache, elf::SymbolCache, proc_map_cache::ProcMapCache, process_info_cache::ProcessInfoCache},
    utils::MMapPathExt, probes::Probe, tail2::HOSTNAME, calltree::SymbolizedFrame,
};

use super::resolved_bpf_sample::ResolvedBpfSample;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum FrameDto {
    Native { module_idx: i32, offset: u32 },
    Python { name: String },
    Kernel { name: String },
}

impl FrameDto {
    pub fn kernel_name(self) -> Option<String> {
        match self {
            FrameDto::Kernel { name } => Some(format!("kernel: {name}")),
            _ => None,
        }
    }
    pub fn python_name(self) -> Option<String> {
        match self {
            FrameDto::Python { name } => Some(format!("python: {name}")),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StackDto {
    pub pid_tgid: PidTgid,
    pub ident: String,
    pub ts_ms: u64,
    pub kernel_frames: Vec<FrameDto>,
    pub native_frames: Vec<FrameDto>,
    pub python_frames: Vec<FrameDto>,
    pub err: Option<()>,
}

impl StackDto {
    pub fn new(pid_tgid: PidTgid, ident: String, ts_ms: u64) -> Self {
        Self {
            pid_tgid,
            ident,
            ts_ms,
            kernel_frames: vec![],
            native_frames: vec![],
            python_frames: vec![],
            err: None,
        }
    }

    /// Mix native, python, kernel stack together into a unified call tree
    pub fn mix(self, modules: &[Arc<Module>], new_modules: &mut impl ModuleMapping) -> Vec<UnsymbolizedFrame> {
        let mut ret = vec![];
        let mut python_frames = self.python_frames.into_iter();

        ret.push(UnsymbolizedFrame::ProcessRoot { pid_tgid: self.pid_tgid, ident: self.ident });

        for f in self.native_frames {
            match f {
                FrameDto::Native { module_idx, offset } => {
                    let module = &modules[module_idx as usize];
                    let new_idx = new_modules.get_index_or_insert(Arc::clone(module)).unwrap();
                    let (py_offset, sz) = module.py_offset;
                    if py_offset <= offset && offset <= py_offset + sz {
                        ret.push(
                            python_frames.next()
                                .map(|i| i.into())
                                .unwrap_or_else(|| UnsymbolizedFrame::Native { module_idx: new_idx, offset })
                        );
                    }
                    else {
                        ret.push(UnsymbolizedFrame::Native { module_idx: new_idx, offset });
                    }
                }
                _ => {
                    unreachable!()
                }
            }
        }

        // ret.append(&mut python_frames.map(|f| Some(ResolvedFrame {
        //     module_idx: 0,
        //     offset: 0,
        //     code_type: CodeType::Python,
        //     name: f.python_name(),
        // })).collect());
        if !ret.is_empty() {
            for kernel_frame in self.kernel_frames {
                ret.push(kernel_frame.into());
            }
        }

        ret
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StackBatchDto {
    pub hostname: String,
    pub probe: String,
    pub stacks: Vec<StackDto>,
    pub modules: Vec<Arc<Module>>,
}

impl StackBatchDto {
    pub fn new(probe: Arc<Probe>) -> Self {
        let probe = serde_json::to_string(&probe).unwrap();
        Self {
            hostname: HOSTNAME.to_string(),
            probe,
            stacks: Default::default(),
            modules: Default::default(),
        }
    }

    pub fn from_stacks(
        probe: Arc<Probe>,
        samples: Vec<ResolvedBpfSample>,
        process_info_cache: &mut ProcessInfoCache,
        proc_map_cache: &mut ProcMapCache,
        module_cache: &mut ModuleCache,
    ) -> Result<StackBatchDto> {
        let mut batch = StackBatchDto::new(probe);
        for bpf_sample in samples {
            let ident = process_info_cache.get(bpf_sample.pid_tgid.pid()).map(|i|i.ident).unwrap_or_default();
            let mut dto = StackDto::new(bpf_sample.pid_tgid, ident, bpf_sample.ts_ms);
            if let Some(s) = bpf_sample.python_stack {
                dto.python_frames = s
                    .frames
                    .into_iter()
                    .rev()
                    .map(|name| FrameDto::Python { name })
                    .collect();
            }
            if let Ok(native_frames) =
                from_native_stack(&mut batch, bpf_sample.native_stack, bpf_sample.pid_tgid.pid(), proc_map_cache, module_cache)
            {
                dto.native_frames = native_frames;
            } else {
                continue;
            }

            if let Some(s) = bpf_sample.kernel_frames {
                dto.kernel_frames = s
                    .into_iter()
                    .map(|i| i.unwrap_or("".to_owned()))
                    .map(|name| FrameDto::Kernel { name })
                    .collect();
            }

            batch.stacks.push(dto);
        }

        Ok(batch)
    }
}

fn from_native_stack(
    batch: &mut StackBatchDto,
    native_stack: Box<NativeStack>,
    pid: u32,
    proc_map_cache: &mut ProcMapCache,
    module_cache: &mut ModuleCache,
) -> Result<Vec<FrameDto>> {
    let len = native_stack.unwind_success.unwrap_or(0);
    let mut native_frames = vec![];
    for address in native_stack.native_stack[..len].iter().rev() {
        let (offset, entry) = lookup(pid, proc_map_cache, *address).context("address not found")?;
        let path = entry
            .pathname
            .path()
            .context("not a path we can resolve")?
            .to_str()
            .context("unable to convert to str")?;
        let module = module_cache.resolve(path).context("module not found")?;
        let module_idx = match batch.modules.iter().position(|m| Arc::ptr_eq(m, &module)) {
            Some(idx) => idx,
            None => {
                batch.modules.push(module);
                batch.modules.len() - 1
            }
        };

        native_frames.push(FrameDto::Native { module_idx: module_idx as i32, offset: offset as u32 });
    }
    Ok(native_frames)
}

fn lookup(pid: u32, proc_map_cache: &mut ProcMapCache, address: usize) -> Option<(usize, MemoryMap)> {
    let proc_maps = proc_map_cache.proc_map(pid).ok()?;
    let translated = || {
        for entry in proc_maps.iter() {
            if address >= entry.address.0 as usize && address < entry.address.1 as usize {
                let translated = address - entry.address.0 as usize + entry.offset as usize;
                return Some((translated, entry.clone()));
            }
        }
        None
    };

    let t = translated();
    if t.is_some() {
        return t;
    }

    proc_map_cache.refresh(pid).ok()?;
    translated()
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Hash)]
pub enum UnsymbolizedFrame {
    None,
    ProcessRoot { pid_tgid: PidTgid, ident: String },
    Native { module_idx: i32, offset: u32 },
    Python { name: String },
    Kernel { name: String },
}

impl Default for UnsymbolizedFrame {
    fn default() -> Self {
        UnsymbolizedFrame::None
    }
}

impl From<FrameDto> for UnsymbolizedFrame {
    fn from(value: FrameDto) -> Self {
        match value {
            FrameDto::Native { module_idx, offset } => Self::Native { module_idx, offset },
            FrameDto::Python { name } => Self::Python { name },
            FrameDto::Kernel { name } => Self::Kernel { name },
        }
    }
}

impl UnsymbolizedFrame {
    pub fn symbolize(self, symbols: &mut SymbolCache, modules: &mut impl ModuleMapping) -> SymbolizedFrame {
        match self {
            UnsymbolizedFrame::None => Default::default(), // TODO: rethink this
            UnsymbolizedFrame::ProcessRoot { pid_tgid, ident } => SymbolizedFrame {
                module_idx: 0,
                offset: 0,
                name: Some(format!("{}:{}", pid_tgid.tgid(), ident)),
                code_type: crate::calltree::CodeType::ProcessRoot
            },
            UnsymbolizedFrame::Native { module_idx, offset } => {
                let module = Arc::clone(&modules.get(module_idx as usize));
                let name = 
                    symbols.entry(&module.path)
                        .and_then(|(_idx, sym)|
                            sym.find(offset as usize));
                // if let Some("_PyEval_EvalFrameDefault") = name.as_deref() {
                //     dbg!(offset);
                // }
                let name = name.map(|s| format!("{}: {}", module.name, s));
                SymbolizedFrame { module_idx, offset, name, code_type: crate::calltree::CodeType::Native }
            },
            UnsymbolizedFrame::Python { name } => SymbolizedFrame { module_idx: 0, offset: 0, name: Some(name), code_type: crate::calltree::CodeType::Python },
            UnsymbolizedFrame::Kernel { name } => SymbolizedFrame { module_idx: 0, offset: 0, name: Some(name), code_type: crate::calltree::CodeType::Kernel },
        }
    }
}

pub struct ModuleMap {
    map: Vec<Arc<Module>>
}

impl ModuleMap {
    pub fn new() -> Self {
        Self {
            map: vec![],
        }
    }
}

impl Default for ModuleMap {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleMapping for ModuleMap {
    fn get_index_or_insert(&mut self, module: Arc<Module>) -> Option<i32> {
        let module_idx = match self.map.iter().position(|m| m.as_ref() == module.as_ref()) {
            Some(idx) => idx,
            None => {
                self.map.push(module);
                self.map.len() - 1
            }
        };

        Some(module_idx as i32)
    }

    fn get(&mut self, idx: usize) -> Arc<Module> {
        Arc::clone(&self.map[idx])
    }
}


pub trait ModuleMapping {
    /// upsert module returning index
    fn get_index_or_insert(&mut self, module: Arc<Module>) -> Option<i32>;

    /// get the module based on index
    fn get(&mut self, idx: usize) -> Arc<Module>;
}