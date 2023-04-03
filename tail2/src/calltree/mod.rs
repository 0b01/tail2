use std::hash::Hash;

use serde::{Deserialize, Serialize};

use crate::{dto::{UnsymbolizedFrame, ModuleMapping}, symbolication::elf::SymbolCache};

use self::inner::CallTreeInner;

pub mod serialize {
    pub use super::inner::serialize::Node;
}

mod inner;
pub mod traits;

pub type UnsymbolizedCallTree = CallTreeInner<UnsymbolizedFrame>;
pub type CallTree = CallTreeInner<SymbolizedFrame>;

impl UnsymbolizedCallTree {
    pub fn symbolize(self, symbols: &mut SymbolCache, modules: &mut impl ModuleMapping) -> CallTree {
        self.map(|f| f.symbolize(symbols, modules))
    }
}

#[repr(u8)]
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug, Hash)]
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

#[derive(Default, Clone, Eq, Serialize, Deserialize, Debug, Hash, PartialEq)]
pub struct SymbolizedFrame {
    pub module_idx: i32,
    pub offset: u32,
    pub name: Option<String>,
    pub code_type: CodeType,
}