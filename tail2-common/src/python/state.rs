use core::fmt::Debug;

use crate::metrics::Metrics;

use super::offsets::PythonOffsets;

pub const PYTHON_STACK_FRAMES_PER_PROG: usize = 80;
pub const FRAME_MAX_LEN: usize = PYTHON_STACK_FRAMES_PER_PROG;
pub const CLASS_NAME_LEN: usize = 32;
pub const FUNCTION_NAME_LEN: usize = 64;
pub const FILE_NAME_LEN: usize = 128;
pub const TASK_COMM_LEN: usize = 16;

#[derive(Copy, Clone, Debug)]
pub enum StackStatus {
    /// Read all the Python stack frames for the running thread, from first to last.
    STACK_STATUS_COMPLETE = 0,
    /// Failed to read a stack frame.
    STACK_STATUS_ERROR = 1,
    /// Succeeded in reading the top STACK_MAX_LEN stack frames, and there were more frames
    /// we didn't read. Try incrementing PYTHON_STACK_PROG_CNT.
    STACK_STATUS_TRUNCATED = 2,
}

/// Identifies the POSIX threads implementation used by a Python process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum pthreads_impl {
    PTI_GLIBC = 0,
    PTI_MUSL = 1,
}

/// This struct contains offsets when used in the offsets map,
/// and resolved vaddrs when used in the pid_data map.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct py_globals {
    pub constant_buffer: usize,        // arbitrary constant offset
    pub _PyThreadState_Current: usize, // 3.6-
    pub _PyRuntime: usize,             // 3.7+
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct pid_data {
    pub pthreads_impl: pthreads_impl,
    pub globals: py_globals,
    pub interp: usize, // vaddr of PyInterpreterState
}

/// Contains all the info we need for a stack frame.
/// Storing `classname` and `file` here means these are duplicated for symbols in the same class or
/// file. This can be avoided with additional maps but it's ok because generally speaking symbols are
/// spread across a variety of files and classes. Using a separate map for `name` would be useless
/// overhead because symbol names are mostly unique.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PythonSymbol {
    pub lineno: u32,
    pub classname: [u8; CLASS_NAME_LEN],
    pub name: [u8; FUNCTION_NAME_LEN],
    pub file: [u8; FILE_NAME_LEN],
    // NOTE: PyFrameObject also has line number but it is typically just the
    // first line of that function and PyCode_Addr2Line needs to be called
    // to get the actual line
}

impl Default for PythonSymbol {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

impl PythonSymbol {
    /// Somehow using Copy trait directly causes bpf verifier to complain...
    /// use a function call so we don't accidentally overflow the stack...
    pub fn copy(&mut self, other: &mut Self) {
        self.lineno = other.lineno;
        self.classname = other.classname;
        self.name = other.name;
        self.file = other.file;
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PythonStack {
    pub comm: [u8; TASK_COMM_LEN],
    pub error_code: Metrics,
    pub stack_status: StackStatus,
    /// instead of storing symbol name here directly, we add it to another
    /// hashmap with Symbols and only store the ids here
    pub frames_len: usize,
    pub frames: [PythonSymbol; FRAME_MAX_LEN],
}

impl PythonStack {
    pub fn uninit() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

impl Debug for PythonStack {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PythonStack")
            .field("comm", &self.comm)
            .field("error_code", &self.error_code)
            .field("stack_status", &self.stack_status)
            .field("stack_len", &self.frames_len)
            .field("stack", &self.frames)
            .finish()
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PythonStack {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PythonSymbol {}
