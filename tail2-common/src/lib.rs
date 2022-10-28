#![no_std]

pub mod runtime_type;
pub mod pidtgid;

pub mod stack;
pub use stack::{Stack, MAX_STACK_SIZE};

pub enum InfoMapKey {
    SentStackCount = 0,
}

pub enum ConfigMapKey {
    DEV = 0,
    INO = 1,
}
