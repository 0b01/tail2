#![no_std]

use pidtgid::PidTgid;

pub mod pidtgid;

pub enum ConfigKey {
    DEV = 0,
    INO = 1,
}

/// max copy size
pub const MAX_STACK_SIZE: usize = 16 << 8;

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct Stack {
    pub stuff: [u8; MAX_STACK_SIZE],
    pub pc: u64,
    pub sp: u64,
    pub fp: u64,
    pub lr: u64,
    pub pidtgid: PidTgid,
}

impl Stack {
    pub fn empty() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stack {}