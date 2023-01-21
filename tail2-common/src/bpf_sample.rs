use crate::{pidtgid::PidTgid, python::state::PythonStack, NativeStack, MAX_USER_STACK};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BpfSample {
    pub pidtgid: PidTgid,
    pub ts: u64,
    pub kernel_stack_id: i64,
    pub native_stack: NativeStack,
    pub python_stack: Option<PythonStack>,
    pub idx: usize,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BpfSample {}
