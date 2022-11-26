use crate::{pidtgid::PidTgid, MAX_USER_STACK, python::state::PythonStack, NativeStack};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Stack {
    pub kernel_stack_id: i64,
    pub user_stack: Option<NativeStack>,
    pub python_stack: Option<PythonStack>,
}

impl Stack {
    pub fn clear(&mut self) {
        self.kernel_stack_id = -1;
        self.user_stack = None;
        self.python_stack = None;
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stack {}