use serde::{Deserialize, Serialize};

#[derive(Eq, Hash, PartialEq, Serialize, Deserialize, Clone, Debug)]
pub enum Scope {
    Pid(u32),
    SystemWide,
}