#![deny(clippy::disallowed_types)]
#![allow(unused, non_camel_case_types, non_snake_case)]
#![cfg_attr(not(feature = "user"), no_std)]

pub mod pidtgid;
pub mod procinfo;
pub mod runtime_type;
pub mod metrics;

pub mod bpf_sample;
pub mod native;
pub mod python;
pub mod tracemgmt;

pub use native::native_stack::NativeStack;

/// Maximum number of frames to unwind
pub const MAX_USER_STACK: usize = 40;

pub enum ConfigMapKey {
    DEV = 0,
    INO = 1,
}
