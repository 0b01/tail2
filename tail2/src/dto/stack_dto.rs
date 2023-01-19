use std::{sync::Arc, path::PathBuf};

use anyhow::{Context, Result};
use procfs::process::{MemoryMap, Process};
use serde::{Deserialize, Serialize};
use tail2_common::{NativeStack, pidtgid::PidTgid};
use tokio::sync::Mutex;

use crate::{
    symbolication::{module::Module, module_cache::ModuleCache, elf::SymbolCache},
    utils::MMapPathExt, calltree::{ResolvedFrame, CodeType}, probes::Probe, tail2::HOSTNAME,
};

use super::resolved_bpf_sample::ResolvedBpfSample;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum FrameDto {
    Native { module_idx: usize, offset: usize },
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
    pub kernel_frames: Vec<FrameDto>,
    pub native_frames: Vec<FrameDto>,
    pub python_frames: Vec<FrameDto>,
    pub err: Option<()>,
}

impl StackDto {
    pub fn new(pid_tgid: PidTgid) -> Self {
        Self {
            pid_tgid,
            kernel_frames: vec![],
            native_frames: vec![],
            python_frames: vec![],
            err: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StackBatchDto {
    pub hostname: String,
    pub probe: String,
    pub stacks: Vec<StackDto>,
    pub modules: Vec<Arc<Module>>,
}

// TODO: remove
pub fn proc_map(pid: u32) -> Result<Vec<MemoryMap>> {
    Process::new(pid as i32)?
        .maps()
        .context("unable to get maps")
}

impl StackBatchDto {
    pub fn new(probe: Probe) -> Self {
        let probe = serde_json::to_string(&probe).unwrap();
        Self {
            hostname: HOSTNAME.to_string(),
            probe,
            stacks: Default::default(),
            modules: Default::default(),
        }
    }

    pub fn from_stacks(
        probe: Probe,
        samples: Vec<ResolvedBpfSample>,
        module_cache: &mut ModuleCache,
    ) -> Result<StackBatchDto> {
        let mut batch = StackBatchDto::new(probe);
        for bpf_sample in samples {
            let mut dto = StackDto::new(bpf_sample.pid_tgid);
            if let Some(s) = bpf_sample.python_stack {
                dto.python_frames = s
                    .frames
                    .into_iter()
                    .rev()
                    .map(|name| FrameDto::Python { name })
                    .collect();
            }
            if let Ok(native_frames) =
                from_native_stack(&mut batch, bpf_sample.native_stack, bpf_sample.pid_tgid.pid(), module_cache)
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
    module_cache: &mut ModuleCache,
) -> Result<Vec<FrameDto>> {
    let len = native_stack.unwind_success.unwrap_or(0);
    let proc_map = proc_map(pid)?;
    let mut native_frames = vec![];
    for address in native_stack.native_stack[..len].iter().rev() {
        let (offset, entry) = lookup(&proc_map, *address).context("address not found")?;
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

        native_frames.push(FrameDto::Native { module_idx, offset });
    }
    Ok(native_frames)
}

fn lookup(proc_map: &[MemoryMap], address: usize) -> Option<(usize, &MemoryMap)> {
    for entry in proc_map.iter() {
        if address >= entry.address.0 as usize && address < entry.address.1 as usize {
            let translated = address - entry.address.0 as usize + entry.offset as usize;
            return Some((translated, entry));
        }
    }
    None
}

pub async fn build_stack(
    stack: StackDto,
    syms: &Arc<Mutex<SymbolCache>>,
    modules: &[Arc<Module>],
) -> Vec<Option<ResolvedFrame>> {
    let mut ret = vec![];
    let mut python_frames = stack.python_frames.into_iter();

    ret.push(Some(ResolvedFrame {
        module_idx: 0,
        offset: 0,
        code_type: CodeType::ProcessRoot,
        name: Some(stack.pid_tgid.pid().to_string()),
    }));

    for f in stack.native_frames {
        match f {
            FrameDto::Native { module_idx, offset } => {
                let module = &modules[module_idx];
                let mut syms = syms.lock().await;
                match syms.entry(&module.path) {
                    Some((module_idx, elf)) => {
                        let name = elf.find(offset);
                        match name.as_deref() {
                            Some("_PyEval_EvalFrameDefault") => {
                                ret.push(python_frames.next().map(|i| ResolvedFrame {
                                    module_idx: 0,
                                    offset: 0,
                                    code_type: CodeType::Python,
                                    name: i.python_name(),
                                }));
                            }
                            _ => {
                                let module_name = PathBuf::from(&module.path);
                                let module_name = module_name
                                    .file_name()
                                    .map(|i| i.to_string_lossy().to_string())
                                    .unwrap_or_default();
                                let fn_name = name.unwrap_or_default();
                                ret.push(Some(ResolvedFrame {
                                    module_idx,
                                    offset,
                                    code_type: CodeType::Native,
                                    name: Some(format!("{module_name}: {fn_name}")),
                                }));
                            }
                        }
                    }
                    None => {
                        ret.push(None);
                    }
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
        for kernel_frame in stack.kernel_frames {
            ret.push(Some(ResolvedFrame {
                module_idx: 0,
                offset: 0,
                code_type: CodeType::Kernel,
                name: kernel_frame.kernel_name(),
            }));
        }
    }

    ret
}