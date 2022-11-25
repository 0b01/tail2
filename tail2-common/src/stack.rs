use crate::{pidtgid::PidTgid, unwinding::aarch64::unwindregs::UnwindRegsAarch64, MAX_USER_STACK, python::state::PythonStack};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Stack {
    pub kernel_stack_id: i64,
    pub user_stack: Option<SystemStack>,
    // pub python_stack: Option<PythonStack>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SystemStack {
    pub pidtgid: PidTgid,
    pub user_stack: [usize; MAX_USER_STACK],
    pub unwind_success: Option<usize>,
}

impl SystemStack {
    pub fn new() -> Self {
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

impl Default for SystemStack {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SystemStack {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stack {}