use crate::{pidtgid::PidTgid, MAX_USER_STACK, python::state::PythonStack, NativeStack};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Stack {
    pub kernel_stack_id: i64,
    pub user_stack: Option<NativeStack>,
    pub python_stack: Option<PythonStack>,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stack {}