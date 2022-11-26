use std::{sync::Arc};

use log::info;
use procfs::process::{all_processes, Process, MemoryMap};
use serde::{Deserialize, Serialize};
use tail2_common::{bpf_sample::BpfSample, NativeStack};
use anyhow::{Result, Context};

use crate::{symbolication::{module::Module, module_cache::{self, ModuleCache}}, utils::MMapPathExt};

use super::resolved_bpf_sample::ResolvedBpfSample;

#[derive(Serialize, Deserialize, Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct FrameDto {
    pub module_idx: usize,
    pub offset: usize,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct StackDto {
    pub frames: Vec<FrameDto>,
    pub success: bool,
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
    pub fn from_stacks(stacks: Vec<ResolvedBpfSample>, module_cache: &mut ModuleCache) -> Result<StackBatchDto> {
        let mut batch = StackBatchDto::default();
        for stack in stacks {
            let mut dto = StackDto::default();
            if let Some(s) = stack.native_stack {
                from_native_stack(&mut batch, &mut dto, s, stack.pid_tgid.pid(), module_cache);
            }
            if let Some(s) = stack.python_stack {
                from_python_stack(&mut dto, s);
            }
            batch.stacks.push(dto);
        }

        Ok(batch)
    }
}

fn from_native_stack(batch: &mut StackBatchDto, dto: &mut StackDto, native_stack: NativeStack, pid: u32, module_cache: &mut ModuleCache) -> Result<()> {
    let len = native_stack.unwind_success.unwrap_or(0);
    let proc_map = proc_map(pid)?;
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

        dto.frames.push(FrameDto {
            module_idx,
            offset,
        });

    }

    Ok(())
}

fn str_from_u8_nul_utf8(utf8_src: &[u8]) -> Result<&str, std::str::Utf8Error> {
    let nul_range_end = utf8_src.iter()
        .position(|&c| c == b'\0')
        .unwrap_or(utf8_src.len()); // default to length if no `\0` present
    ::std::str::from_utf8(&utf8_src[0..nul_range_end])
}

fn from_python_stack(dto: &mut StackDto, s: tail2_common::python::state::PythonStack) -> Result<()> {
    for f in &s.frames[..s.frames_len] {
        if let Ok(name) = str_from_u8_nul_utf8(&f.name) {
            info!("{}", name);
        }
    }
    Ok(())
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
            let limit = req.limits().get("stack").unwrap_or_else(||20.megabytes());

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