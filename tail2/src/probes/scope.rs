use serde::{Deserialize, Serialize};

#[derive(Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Scope {
    Pid(u32),
    SystemWide,
}