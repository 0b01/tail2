use crate::native::unwinding::error::Error;

macro_rules! count {
    () => (0usize);
    ( $x:tt $($xs:tt)* ) => (1usize + count!($($xs)*));
}

/// https://stackoverflow.com/a/64678145/10854888
macro_rules! iterable_enum {
    ($(#[$derives:meta])* $(vis $visibility:vis)? enum $name:ident { $($(#[$nested_meta:meta])* $member:ident),* }) => {
        const COUNT_MEMBERS: usize = count!($($member)*);
        $(#[$derives])*
        $($visibility)? enum $name {
            $($(#[$nested_meta])* $member),*
        }
        impl $name {
            pub const fn iter() -> [$name; COUNT_MEMBERS] {
                [$($name::$member,)*]
            }
        }
    };
}


iterable_enum! {
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    #[repr(u32)]
    vis pub enum Metrics {
        SentStackCount,

        ErrSample_CantAlloc,
        ErrSample_NoPidInfo,
        ErrSample_BinarySearch,

        ErrUnw_InvalidRule,
        ErrUnw_CouldNotReadStack,
        ErrUnw_FramepointerUnwindingMovedBackwards,
        ErrUnw_DidNotAdvance,
        ErrUnw_IntegerOverflow,
        ErrUnw_ReturnAddressIsNull,

        /// New pid seen in the tracee
        TraceMgmt_NewPid,
        TraceMgmt_NewPidAlreadyNotified,
        TraceMgmt_PidErr,

        ErrPy_NoStack,
        /// No error
        ErrPy_NONE,
        /// Expected one of _PyThreadState_Current/_PyRuntime to be set, but both are NULL.
        ErrPy_MISSING_PYSTATE,
        /// Read _PyThreadState_Current and it's NULL. This means the GIL is released, and we have to wait
        /// until it is grabbed again to get the PyInterpreterState.
        ErrPy_THREAD_STATE_NULL,
        /// Read the address of PyInterpreterState from _PyThreadState_Current/_PyRuntime and got NULL.
        /// This can happen at process startup/shutdown when the interpreter hasn't been created yet or has been
        /// torn down.
        ErrPy_INTERPRETER_NULL,
        /// When searching for the PyThreadState, we iterated through the maximum thread states and didn't find
        /// a match. Increase the maximum number of thread states to iterate.
        ErrPy_TOO_MANY_THREADS,
        /// When searching for the PyThreadState, we iterated through _all_ the thread states and didn't find
        /// a match.
        ErrPy_THREAD_STATE_NOT_FOUND,
        /// The frame pointer in the current PyThreadState is NULL, meaning the Python stack for this Python
        /// thread is empty.
        ErrPy_EMPTY_STACK,
        /// unused?
        ErrPy_FRAME_CODE_IS_NULL,
        /// Reading data from the thread descriptor (at %fs) faulted. This can happen when a new thread is created but pthreads
        /// has not initialized in that thread yet.
        ErrPy_BAD_FSBASE,
        /// The pthreads implementation set for the process is invalid.
        ErrPy_INVALID_PTHREADS_IMPL,
        /// Read the pointer to the head of the thread states list from the PyInterpreterState and got NULL.
        ErrPy_THREAD_STATE_HEAD_NULL,
        /// Reading a field from a thread state in the thread states list failed.
        ErrPy_BAD_THREAD_STATE,
        /// A tail call to a BPF program failed.
        ErrPy_CALL_FAILED,
        ///
        ErrPy_CANT_ALLOC,
        ///
        ErrPy_NO_PID,
        ///
        ErrPy_READ_FRAME,
        ErrPy_GET_FIRST_ARG,
        ErrPy_FIRST_ARG_NOT_FOUND,

        /// Enum Max
        Max
    }
}

impl From<Error> for Metrics {
    fn from(value: Error) -> Self {
        match value {
            Error::InvalidRule => Self::ErrUnw_InvalidRule,
            Error::CouldNotReadStack(_) => Self::ErrUnw_CouldNotReadStack,
            Error::FramepointerUnwindingMovedBackwards => Self::ErrUnw_FramepointerUnwindingMovedBackwards,
            Error::DidNotAdvance => Self::ErrUnw_DidNotAdvance,
            Error::IntegerOverflow => Self::ErrUnw_IntegerOverflow,
            Error::ReturnAddressIsNull => Self::ErrUnw_ReturnAddressIsNull,
        }
    }
}