use serde::{Deserialize, Serialize};

use self::inner::CallTreeInner;

pub mod inner;
pub mod traits;

pub type CallTree = CallTreeInner<Option<ResolvedFrame>>;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub enum CodeType {
    Native = 0,
    Python = 1,
    Kernel = 2,
    ProcessRoot = 3,
}

#[derive(Clone, Eq, Serialize, Deserialize, Debug)]
pub struct ResolvedFrame {
    pub module_idx: usize,
    pub offset: usize,
    pub code_type: CodeType,
    pub name: Option<String>,
}

impl PartialEq for ResolvedFrame {
    fn eq(&self, other: &Self) -> bool {
        self.module_idx == other.module_idx && self.name == other.name
    }
}
