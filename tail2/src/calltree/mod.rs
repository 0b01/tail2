use serde::{Deserialize, Serialize};

use crate::dto::UnsymbolizedFrame;

use self::inner::CallTreeInner;

pub mod serialize {
    pub use super::inner::serialize::Node;
}

mod inner;
pub mod traits;

pub type UnsymbolizedCallTree = CallTreeInner<UnsymbolizedFrame>;
pub type CallTree = CallTreeInner<SymbolizedFrame>;

#[repr(u8)]
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub enum CodeType {
    Unknown = 0,
    Native = 1,
    Python = 2,
    Kernel = 3,
    ProcessRoot = 4,
}

impl Default for CodeType {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Default, Clone, Eq, Serialize, Deserialize, Debug)]
pub struct SymbolizedFrame {
    pub module_idx: u32,
    pub offset: u32,
    pub name: Option<String>,
    pub code_type: CodeType,
}

impl PartialEq for SymbolizedFrame {
    fn eq(&self, other: &Self) -> bool {
        self.module_idx == other.module_idx && self.name == other.name
    }
}
