use crate::pidtgid::PidTgid;

/// page size in bytes
pub const PAGE_SIZE: usize = 4096;

/// user stack page count
/// TODO: out of all things, tokio crashes when this gets to 3...
pub const USER_STACK_PAGES: usize = 2;

/// max copy size
pub const MAX_STACK_SIZE: usize = USER_STACK_PAGES * PAGE_SIZE;

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct Stack {
    pub raw_user_stack: [u8; MAX_STACK_SIZE],
    pub user_stack_len: usize,
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
    #[inline]
    pub fn pid(&self) -> u32 {
        self.pidtgid.pid()
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stack {}