use anyhow::Result;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, sync::Arc, collections::HashMap, path::Path};

use symbolic::{
    common::ByteView,
    debuginfo::{elf::ElfObject, ObjectKind},
};
#[cfg(target_arch = "aarch64")]
use tail2_common::native::unwinding::aarch64::unwind_table::UnwindTable;
#[cfg(target_arch = "x86_64")]
use tail2_common::native::unwinding::x86_64::unwind_table::UnwindTable;

/// a map from debug_id to the offset and size of method _PyEval_EvalFrameDefault
pub static PYTHON_DEBUG_IDS: Lazy<HashMap<&'static str, (u32, u32)>> = Lazy::new(|| {
    let mut ret = HashMap::new();
    ret.insert("e41d84a1-ecf4-4594-a10b-ff638afa4c72", (966624, 42316)); // 3.10
    ret.insert("d719f365-a65f-1262-0654-ed39ed608b11", (0x4a3f10, 0)); // 3.11
    ret
});

#[derive(Serialize, Deserialize)]
pub struct Module {
    #[serde(skip)]
    pub unwind_table: Option<Arc<UnwindTable>>,
    pub path: String,
    pub name: String,
    pub arch: i32,
    pub kind: ObjectKind,
    pub debug_id: String,
    pub py_offset: Option<(u32, u32)>,
}

impl Eq for Module {}
impl PartialEq for Module {
    fn eq(&self, other: &Self) -> bool {
        self.debug_id == other.debug_id
    }
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
        let py_offset = PYTHON_DEBUG_IDS.get(debug_id.as_str()).copied();
        let name = Path::file_stem(&Path::new(path)).unwrap_or_default().to_string_lossy().to_string();
        Ok(Self {
            unwind_table: Some(unwind_table),
            path: path.to_owned(),
            arch: obj.arch() as i32,
            name,
            kind: obj.kind(),
            debug_id,
            py_offset,
        })
    }
}
