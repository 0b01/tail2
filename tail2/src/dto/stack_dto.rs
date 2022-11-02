use std::sync::Arc;

use procfs::process::{all_processes, Process, MemoryMap};
use serde::{Deserialize, Serialize};
use tail2_common::Stack;
use anyhow::{Result, Context};

use crate::{symbolication::{module::Module, module_cache::{self, ModuleCache}}, utils::MMapPathExt};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct FrameDto {
    pub module_idx: usize,
    pub offset: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct StackDto {
    pub frames: Vec<FrameDto>,
    pub modules: Vec<Arc<Module>>,
    pub success: bool,
}

impl StackDto {
    pub fn from_stack(stack: Stack, module_cache: &mut ModuleCache) -> Result<StackDto> {
        let mut dto = StackDto::default();
        let len = stack.unwind_success.unwrap_or(0);
        let proc_map = Process::new(stack.pid() as i32)?.maps()?;
        for address in &stack.user_stack[..len] {
            let (offset, entry) = lookup(&proc_map, *address).context("address not found")?;
            let path = entry.pathname
                .path()
                .context("not a path we can resolve")?
                .to_str().context("unable to convert to str")?;
            let module = module_cache.resolve(path).context("module not found")?;
            let module_idx = match dto.modules.iter().position(|m| Arc::ptr_eq(m, &module)) {
                Some(idx) => idx,
                None => {
                    dto.modules.push(module);
                    dto.modules.len() - 1
                }
            };

            dto.frames.push(FrameDto {
                module_idx,
                offset,
            });
        }
        dbg!(&dto);
        Ok(dto)
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
    impl<'r> FromData<'r> for StackDto {
        type Error = FromDataError;

        async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> data::Outcome<'r, Self> {
            use rocket::outcome::Outcome::*;

            // Use a configured limit with name 'stack' or fallback to default.
            let limit = req.limits().get("stack").unwrap_or(2.megabytes());

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