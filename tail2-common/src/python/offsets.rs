structstruck::strike! {
    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct PythonOffsets {
        pub py_object: #[derive(Clone, Copy, Debug)] struct {
            pub ob_type: usize
        },
        pub string: #[derive(Clone, Copy, Debug)] struct {
            pub data: usize,
            pub size: i64,
        },
        pub py_type_object: #[derive(Clone, Copy, Debug)] struct {
            pub tp_name: usize
        },
        pub py_thread_state: #[derive(Clone, Copy, Debug)] struct {
            pub next: usize,
            pub interp: usize,
            pub frame: usize,
            pub thread: usize,
        },
        pub py_interpreter_state: #[derive(Clone, Copy, Debug)] struct {
            pub tstate_head: usize,
        },
        pub py_runtime_state: #[derive(Clone, Copy, Debug)] struct {
            pub interp_main: usize,
        },
        pub py_frame_object: #[derive(Clone, Copy, Debug)] struct {
            pub f_back: usize,
            pub f_code: usize,
            pub f_lineno: usize,
            pub f_localsplus: usize,
        },
        pub py_code_object: #[derive(Clone, Copy, Debug)] struct {
            pub co_filename: usize,
            pub co_name: usize,
            pub co_varnames: usize,
            pub co_firstlineno: usize,
        },
        pub py_tuple_object: #[derive(Clone, Copy, Debug)] struct {
            pub ob_item: usize,
        },
    }
}

/*
Struct offsets per Python version
Most of these fields are named according to the struct name in Python and are defined as structs
whose fields are 64-bit offsets named according the required fields declared in the original struct
There are a couple of exceptions:
1 String - offsets are into Python string object struct Since the representation of strings varies
   greatly among versions and depends on encoding and interning, the field names do not correspond
   to the fields of any particular struct `data` is the offset to the first character of the string,
   and `size` is the offset to the 32-bit integer representing the length in bytes (not characters)
2 PyRuntimeStateinterp_main - corresponds to offsetof(_PyRuntimeState, interpretersmain)
3 PyThreadStatethread - this field's name is "thread_id" in some Python versions
*/

pub const PY27_OFFSETS: PythonOffsets = PythonOffsets {
    py_object: PyObject { ob_type: 8 },
    string: String {
        data: 36, // offsetof(PyStringObject, ob_sval)
        size: 16, // offsetof(PyVarObject, ob_size)
    },
    py_type_object: PyTypeObject { tp_name: 24 },
    py_thread_state: PyThreadState {
        next: 0,
        interp: 8,
        frame: 16,
        thread: 144,
    },
    py_interpreter_state: PyInterpreterState { tstate_head: 8 },
    py_runtime_state: PyRuntimeState {
        interp_main: 0, // N/A
    },
    py_frame_object: PyFrameObject {
        f_back: 24,
        f_code: 32,
        f_lineno: 124,
        f_localsplus: 376,
    },
    py_code_object: PyCodeObject {
        co_filename: 80,
        co_name: 88,
        co_varnames: 56,
        co_firstlineno: 96,
    },
    py_tuple_object: PyTupleObject { ob_item: 24 },
};

pub const PY36_OFFSETS: PythonOffsets = PythonOffsets {
    py_object: PyObject { ob_type: 8 },
    string: String {
        data: 48, // sizeof(PyASCIIObject)
        size: 16, // offsetof(PyVarObject, ob_size)
    },
    py_type_object: PyTypeObject { tp_name: 24 },
    py_thread_state: PyThreadState {
        next: 8,
        interp: 16,
        frame: 24,
        thread: 152,
    },
    py_interpreter_state: PyInterpreterState { tstate_head: 8 },
    py_runtime_state: PyRuntimeState {
        interp_main: 0, // N/A
    },
    py_frame_object: PyFrameObject {
        f_back: 24,
        f_code: 32,
        f_lineno: 124,
        f_localsplus: 376,
    },
    py_code_object: PyCodeObject {
        co_filename: 96,
        co_name: 104,
        co_varnames: 64,
        co_firstlineno: 36,
    },
    py_tuple_object: PyTupleObject { ob_item: 24 },
};

pub const PY37_OFFSETS: PythonOffsets = PythonOffsets {
    py_object: PyObject { ob_type: 8 },
    string: String {
        data: 48, // sizeof(PyASCIIObject)
        size: 16, // offsetof(PyVarObject, ob_size)
    },
    py_type_object: PyTypeObject { tp_name: 24 },
    py_thread_state: PyThreadState {
        next: 8,
        interp: 16,
        frame: 24,
        thread: 176,
    },
    py_interpreter_state: PyInterpreterState { tstate_head: 8 },
    py_runtime_state: PyRuntimeState { interp_main: 40 },
    py_frame_object: PyFrameObject {
        f_back: 24,
        f_code: 32,
        f_lineno: 108,
        f_localsplus: 360,
    },
    py_code_object: PyCodeObject {
        co_filename: 96,
        co_name: 104,
        co_varnames: 64,
        co_firstlineno: 36,
    },
    py_tuple_object: PyTupleObject { ob_item: 24 },
};

pub const PY38_OFFSETS: PythonOffsets = PythonOffsets {
    py_object: PyObject { ob_type: 8 },
    string: String {
        data: 48, // sizeof(PyASCIIObject)
        size: 16, // offsetof(PyVarObject, ob_size)
    },
    py_type_object: PyTypeObject { tp_name: 24 },
    py_thread_state: PyThreadState {
        next: 8,
        interp: 16,
        frame: 24,
        thread: 176,
    },
    py_interpreter_state: PyInterpreterState { tstate_head: 8 },
    py_runtime_state: PyRuntimeState { interp_main: 40 },
    py_frame_object: PyFrameObject {
        f_back: 24,
        f_code: 32,
        f_lineno: 108,
        f_localsplus: 360,
    },
    py_code_object: PyCodeObject {
        co_filename: 104,
        co_name: 112,
        co_varnames: 72,
        co_firstlineno: 40,
    },
    py_tuple_object: PyTupleObject { ob_item: 24 },
};

pub const PY310_OFFSETS: PythonOffsets = PythonOffsets {
    py_object: PyObject { ob_type: 8 },
    string: String {
        data: 48, // offsetof(PyStringObject, ob_sval)
        size: -1, // offsetof(PyVarObject, ob_size)
    },
    py_type_object: PyTypeObject { tp_name: 24 },
    py_thread_state: PyThreadState {
        next: 8,
        interp: 16,
        frame: 24,
        thread: 176,
    },
    py_interpreter_state: PyInterpreterState { tstate_head: 8 },
    py_runtime_state: PyRuntimeState {
        interp_main: 40, // N/A
    },
    py_frame_object: PyFrameObject {
        f_back: 24,
        f_code: 32,
        f_lineno: 100,
        f_localsplus: 352,
    },
    py_code_object: PyCodeObject {
        co_filename: 104,
        co_name: 112,
        co_varnames: 72,
        co_firstlineno: 40,
    },
    py_tuple_object: PyTupleObject { ob_item: 24 },
};
