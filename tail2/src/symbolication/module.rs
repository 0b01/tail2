use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, fmt::Debug};

use symbolic::{common::{ByteView}, debuginfo::{elf::ElfObject, ObjectKind}};
use tail2_common::unwinding::aarch64::unwind_table::UnwindTable;

#[derive(Serialize, Deserialize)]
pub struct Module {
    #[serde(skip)]
    pub unwind_table: Option<Arc<UnwindTable>>,
    pub path: String,
    pub arch: i32,
    pub kind: ObjectKind,
    pub debug_id: String,
}

impl Debug for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Module")
            .field("path", &self.path)
            .field("arch", &self.arch)
            .field("kind", &self.kind)
            .field("debug_id", &self.debug_id)
            .finish()
    }
}

impl Module {
    pub fn from_path(path: &str) -> Result<Self> {
        let path = path.as_ref();
        let buffer = ByteView::open(&path)?;
        let obj = ElfObject::parse(&buffer)?;
        let unwind_table = Arc::new(UnwindTable::from_path(path)?);
        Ok(Self {
            unwind_table: Some(unwind_table),
            path: path.to_owned(),
            arch: obj.arch() as i32,
            kind: obj.kind(),
            debug_id: obj.debug_id().to_string(),
        })
    }
}
