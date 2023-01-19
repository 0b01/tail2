use anyhow::Result;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, sync::Arc, collections::HashMap};

use symbolic::{
    common::ByteView,
    debuginfo::{elf::ElfObject, ObjectKind},
};
#[cfg(target_arch = "aarch64")]
use tail2_common::native::unwinding::aarch64::unwind_table::UnwindTable;
#[cfg(target_arch = "x86_64")]
use tail2_common::native::unwinding::x86_64::unwind_table::UnwindTable;

/// a map from debug_id to the offset of symbol _PyEval_EvalFrameDefault
pub static PYTHON_DEBUG_IDS: Lazy<HashMap<&'static str, u32>> = Lazy::new(|| {
    let mut ret = HashMap::new();
    ret.insert("e41d84a1-ecf4-4594-a10b-ff638afa4c72", 0x0ebfe0); // 3.10
    ret.insert("d719f365-a65f-1262-0654-ed39ed608b11", 0x4a3f10); // 3.11
    ret
});

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct Module {
    #[serde(skip)]
    pub unwind_table: Option<Arc<UnwindTable>>,
    pub path: String,
    pub arch: i32,
    pub kind: ObjectKind,
    pub debug_id: String,
    pub is_python_module: bool,
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
        let buffer = ByteView::open(path)?;
        let obj = ElfObject::parse(&buffer)?;
        let unwind_table = Arc::new(UnwindTable::from_path(path)?);
        let debug_id = obj.debug_id().to_string();
        let is_python_module = PYTHON_DEBUG_IDS.contains_key(debug_id.as_str());
        Ok(Self {
            unwind_table: Some(unwind_table),
            path: path.to_owned(),
            arch: obj.arch() as i32,
            kind: obj.kind(),
            debug_id,
            is_python_module,
        })
    }

    pub fn py_offset(&self) -> Option<u32> {
        if self.is_python_module {
            let ret = PYTHON_DEBUG_IDS.get(self.debug_id.as_str()).unwrap();
            Some(*ret)
        } else {
            None
        }
    }
}
