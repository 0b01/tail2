#![no_std]

pub enum ConfigKey {
    DEV = 0,
    INO = 1,
}

// TODO: Somehow the max must be 51...
pub const MAX_STACK_SIZE: usize = 51;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Stack {
    pub stuff: [u8; MAX_STACK_SIZE],
    pub pc: u64,
    pub sp: u64,
}

impl Stack {
    pub fn new() -> Self {
        Self {
            stuff: [0u8; MAX_STACK_SIZE],
            pc: 0,
            sp: 0,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stack {}