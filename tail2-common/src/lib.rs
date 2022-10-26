#![no_std]

pub mod pidtgid;

pub mod stack;
pub use stack::{Stack, MAX_STACK_SIZE};

pub mod new_proc_event;

pub enum ConfigKey {
    DEV = 0,
    INO = 1,
}
