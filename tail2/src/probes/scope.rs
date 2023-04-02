use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

#[derive(Eq, Hash, PartialEq, Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum Scope {
    Pid {
        pid: u32,
    },
    SystemWide,
}

impl Display for Scope {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Scope::Pid { pid } => write!(f, "pid{}", pid),
            Scope::SystemWide => write!(f, "system_wide"),
        }
    }
}