use serde::{Deserialize, Serialize};

#[derive(Eq, Hash, PartialEq, Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum Scope {
    Pid {
        pid: u32,
    },
    SystemWide,
}