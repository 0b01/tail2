use crate::{pidtgid::PidTgid, MAX_USER_STACK, python::state::PythonStack, NativeStack};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BpfSample {
    pub pidtgid: PidTgid,
    pub kernel_stack_id: i64,
    pub native_stack: Option<NativeStack>,
    pub python_stack: Option<PythonStack>,
}

impl BpfSample {
    pub fn clear(&mut self) {
        self.pidtgid = PidTgid::new();
        self.kernel_stack_id = -1;
        self.native_stack = None;
        self.python_stack = None;
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BpfSample {}