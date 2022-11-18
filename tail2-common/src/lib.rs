#![allow(unused)]
#![allow(non_camel_case_types, non_snake_case)]
#![cfg_attr(not(feature = "user"), no_std)]

pub mod runtime_type;
pub mod pidtgid;
pub mod procinfo;

pub mod stack;
pub mod unwinding;
pub mod python;
pub use stack::Stack;

/// Maximum number of frames to unwind 
pub const MAX_USER_STACK: usize = 40;

pub enum RunStatsKey {
    SentStackCount = 0,
}

pub enum ConfigMapKey {
    DEV = 0,
    INO = 1,
}
