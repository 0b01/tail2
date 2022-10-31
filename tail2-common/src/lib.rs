#![allow(unused)]
#![cfg_attr(not(feature = "user"), no_std)]

pub mod runtime_type;
pub mod pidtgid;
pub mod procinfo;

pub mod stack;
pub mod unwinding;
pub use stack::Stack;

pub enum InfoMapKey {
    SentStackCount = 0,
}

pub enum ConfigMapKey {
    DEV = 0,
    INO = 1,
}
