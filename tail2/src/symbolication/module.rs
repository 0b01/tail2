use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::rc::Rc;

use symbolic::{common::{ByteView}, debuginfo::{elf::ElfObject, ObjectKind}};
use tail2_common::unwinding::aarch64::unwind_table::UnwindTable;

#[derive(Serialize, Deserialize, Debug)]
pub struct Module {
    #[serde(skip)]
    pub unwind_table: Option<Rc<UnwindTable>>,
    pub path: String,
    pub arch: i32,
    pub kind: ObjectKind,
    pub debug_id: String,
}

impl Module {
    pub fn from_path(path: &str) -> Result<Self> {
        let path = path.as_ref();
        let buffer = ByteView::open(&path)?;
        let obj = ElfObject::parse(&buffer)?;
        let unwind_table = Rc::new(UnwindTable::from_path(path)?);
        Ok(Self {
            unwind_table: Some(unwind_table),
            path: path.to_owned(),
            arch: obj.arch() as i32,
            kind: obj.kind(),
            debug_id: obj.debug_id().to_string(),
        })
    }
}
