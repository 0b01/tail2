use std::{sync::Arc};

use log::info;
use procfs::process::{all_processes, Process, MemoryMap};
use serde::{Deserialize, Serialize};
use tail2_common::{bpf_sample::BpfSample, NativeStack, python::{state::PythonStack, self}};
use anyhow::{Result, Context};

use crate::{symbolication::{module::Module, module_cache::{self, ModuleCache}}, utils::MMapPathExt};

use super::resolved_bpf_sample::{ResolvedBpfSample, ResolvedPythonFrames};

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum FrameDto {
    Native {
        module_idx: usize,
        offset: usize,
    },
    Python {
        name: String,
    },
    Kernel {
        name: String,
    },
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
    pub kernel_frames: Vec<FrameDto>,
    pub native_frames: Vec<FrameDto>,
    pub python_frames: Vec<FrameDto>,
    pub err: Option<()>,
}

impl Default for StackDto {
    fn default() -> Self {
        Self::new()
    }
}

impl StackDto {
    pub fn new() -> Self {
        Self {
            kernel_frames: vec![],
            native_frames: vec![],
            python_frames: vec![],
            err: todo!(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct StackBatchDto {
    pub stacks: Vec<StackDto>,
    pub modules: Vec<Arc<Module>>,
}

pub fn proc_map(pid: u32) -> Result<Vec<MemoryMap>> {
    Process::new(pid as i32)?.maps().context("unable to get maps")
}

impl StackBatchDto {
    pub fn from_stacks(samples: Vec<ResolvedBpfSample>, module_cache: &mut ModuleCache) -> Result<StackBatchDto> {
        let mut batch = StackBatchDto::default();
        for bpf_sample in samples {
            let mut dto = StackDto::new();
            if let Some(s) = bpf_sample.python_stack {
                dto.python_frames = s.frames.into_iter().rev().map(|name| FrameDto::Python { name }).collect();
            }
            if let Some(s) = bpf_sample.native_stack {
                if let Ok(native_frames ) = from_native_stack(&mut batch, s, bpf_sample.pid_tgid.pid(), module_cache) {
                    dto.native_frames = native_frames;
                }
            }
            if let Some(s) = bpf_sample.kernel_frames {
                dto.kernel_frames = s.into_iter()
                    .map(|i| i.unwrap_or("".to_owned()))
                    .map(|name| FrameDto::Kernel { name })
                    .collect();
            }
            batch.stacks.push(dto);
        }

        Ok(batch)
    }
}

fn from_native_stack(batch: &mut StackBatchDto, native_stack: NativeStack, pid: u32, module_cache: &mut ModuleCache) -> Result<Vec<FrameDto>> {
    let len = native_stack.unwind_success.unwrap_or(0);
    let proc_map = proc_map(pid)?;
    let mut native_frames = vec![];
    for address in native_stack.native_stack[..len].iter().rev() {
        let (offset, entry) = lookup(&proc_map, *address).context("address not found")?;
        let path = entry.pathname
            .path()
            .context("not a path we can resolve")?
            .to_str().context("unable to convert to str")?;
        let module = module_cache.resolve(path).context("module not found")?;
        let module_idx = match batch.modules.iter().position(|m| Arc::ptr_eq(m, &module)) {
            Some(idx) => idx,
            None => {
                batch.modules.push(module);
                batch.modules.len() - 1
            }
        };

        native_frames.push(FrameDto::Native {
            module_idx,
            offset,
        });
    }
    Ok(native_frames)
}

fn str_from_u8_nul_utf8(utf8_src: &[u8]) -> Result<&str, std::str::Utf8Error> {
    let nul_range_end = utf8_src.iter()
        .position(|&c| c == b'\0')
        .unwrap_or(utf8_src.len()); // default to length if no `\0` present
    ::std::str::from_utf8(&utf8_src[0..nul_range_end])
}

fn lookup(proc_map: &[MemoryMap], address: usize) -> Option<(usize, &MemoryMap)> {
    for entry in proc_map.iter() {
        if address >= entry.address.0 as usize && address < entry.address.1  as usize{
            let translated = address - entry.address.0 as usize + entry.offset as usize;
            return Some((translated, entry));
        }
    }
    None
}

#[cfg(feature = "server")]
mod server {
    use super::*;
    use rocket::{data::{FromData, self, ToByteUnit}, Request, Data, http::Status};
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum FromDataError {
        #[error("payload too large")]
        PayloadTooLarge,
        #[error("server error")]
        ServerError(String),
        #[error("serialization")]
        Serialization,
    }

    #[rocket::async_trait]
    impl<'r> FromData<'r> for StackBatchDto {
        type Error = FromDataError;

        async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> data::Outcome<'r, Self> {
            use rocket::outcome::Outcome::*;

            // Use a configured limit with name 'stack' or fallback to default.
            let limit = req.limits().get("stack").unwrap_or_else(||40.megabytes());

            // Read the data into a string.
            let buf = match data.open(limit).into_bytes().await {
                Ok(string) if string.is_complete() => string.into_inner(),
                Ok(_) => return Failure((Status::PayloadTooLarge, FromDataError::PayloadTooLarge)),
                Err(e) => return Failure((Status::InternalServerError, FromDataError::ServerError(e.to_string()))),
            };
            let ret = match bincode::deserialize(&buf) {
                Ok(ret) => ret,
                Err(_) => return Failure((Status::ImATeapot, FromDataError::Serialization)),
            };
    
            Success(ret)
        }
    }
}