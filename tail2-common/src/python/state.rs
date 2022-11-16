use super::offsets::PythonOffsets;

pub const PYTHON_STACK_FRAMES_PER_PROG: usize = 16;
pub const PYTHON_STACK_PROG_CNT: usize = 5;
pub const STACK_MAX_LEN: usize = (PYTHON_STACK_FRAMES_PER_PROG * PYTHON_STACK_PROG_CNT);
pub const CLASS_NAME_LEN: usize = 32;
pub const FUNCTION_NAME_LEN: usize = 64;
pub const FILE_NAME_LEN: usize = 256;
pub const TASK_COMM_LEN: usize = 16;

#[derive(Copy, Clone, Debug)]
pub enum ErrorCode {
    /// No error
    ERROR_NONE = 0,
    /// Expected one of _PyThreadState_Current/_PyRuntime to be set, but both are NULL.
    ERROR_MISSING_PYSTATE = 1,
    /// Read _PyThreadState_Current and it's NULL. This means the GIL is released, and we have to wait
    /// until it is grabbed again to get the PyInterpreterState.
    ERROR_THREAD_STATE_NULL = 2,
    /// Read the address of PyInterpreterState from _PyThreadState_Current/_PyRuntime and got NULL.
    /// This can happen at process startup/shutdown when the interpreter hasn't been created yet or has been
    /// torn down.
    ERROR_INTERPRETER_NULL = 3,
    /// When searching for the PyThreadState, we iterated through the maximum thread states and didn't find
    /// a match. Increase the maximum number of thread states to iterate.
    ERROR_TOO_MANY_THREADS = 4,
    /// When searching for the PyThreadState, we iterated through _all_ the thread states and didn't find
    /// a match.
    ERROR_THREAD_STATE_NOT_FOUND = 5,
    /// The frame pointer in the current PyThreadState is NULL, meaning the Python stack for this Python
    /// thread is empty.
    ERROR_EMPTY_STACK = 6,
    /// unused?
    ERROR_FRAME_CODE_IS_NULL = 7,
    /// Reading data from the thread descriptor (at %fs) faulted. This can happen when a new thread is created but pthreads
    /// has not initialized in that thread yet.
    ERROR_BAD_FSBASE = 8,
    /// The pthreads implementation set for the process is invalid.
    ERROR_INVALID_PTHREADS_IMPL = 9,
    /// Read the pointer to the head of the thread states list from the PyInterpreterState and got NULL.
    ERROR_THREAD_STATE_HEAD_NULL = 10,
    /// Reading a field from a thread state in the thread states list failed.
    ERROR_BAD_THREAD_STATE = 11,
    /// A tail call to a BPF program failed.
    ERROR_CALL_FAILED = 12,
    /// 
    CANT_ALLOC = 13,
    ///
    NO_PID,
}

#[derive(Copy, Clone)]
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
#[derive(Clone, Copy, Debug)]
pub struct py_globals {
    pub constant_buffer: i64,  // arbitrary constant offset
    pub py_thread_state_current: i64, // 3.6-
    pub py_runtime: i64,  // 3.7+
}

#[derive(Copy, Clone, Debug)]
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
#[derive(Copy, Clone)]
pub struct PythonSymbol {
  lineno: u32,
  classname: [u8; CLASS_NAME_LEN],
  name: [u8; FUNCTION_NAME_LEN],
  file: [u8; FILE_NAME_LEN],
  // NOTE: PyFrameObject also has line number but it is typically just the
  // first line of that function and PyCode_Addr2Line needs to be called
  // to get the actual line
}

#[derive(Copy, Clone)]
pub struct Event {
    pub pid: u32,
    pub tid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub error_code: ErrorCode,
    pub stack_status: StackStatus,
    pub kernel_stack_id: i64,
    /// instead of storing symbol name here directly, we add it to another
    /// hashmap with Symbols and only store the ids here
    pub stack_len: i32,
    pub stack: [i32; STACK_MAX_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PythonSymbol {}