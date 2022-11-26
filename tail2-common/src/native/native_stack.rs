use core::mem::MaybeUninit;

use crate::{MAX_USER_STACK, pidtgid::PidTgid};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NativeStack {
    pub pidtgid: PidTgid,
    pub user_stack: [usize; MAX_USER_STACK],
    pub unwind_success: Option<usize>,
}

impl NativeStack {
    pub fn new() -> Self {
        Self {
            pidtgid: unsafe { core::mem::zeroed() },
            user_stack: [0; MAX_USER_STACK],
            unwind_success: None,
        }
    }

    pub fn uninit() -> Self {
        unsafe { MaybeUninit::uninit().assume_init() }
    }

    #[inline(always)]
    pub fn pid(&self) -> u32 {
        self.pidtgid.pid()
    }
}

impl Default for NativeStack {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeStack {}
