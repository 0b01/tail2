use crate::{pidtgid::PidTgid, unwinding::aarch64::unwindregs::UnwindRegsAarch64, MAX_USER_STACK};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Stack {
    pub pidtgid: PidTgid,
    pub user_stack: [usize; MAX_USER_STACK],
    pub unwind_success: Option<usize>,
}

impl Stack {
    pub fn empty() -> Self {
        Self {
            pidtgid: unsafe { core::mem::zeroed() },
            user_stack: [0; MAX_USER_STACK],
            unwind_success: None,
        }
    }

    #[inline]
    pub fn pid(&self) -> u32 {
        self.pidtgid.pid()
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stack {}