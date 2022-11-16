structstruck::strike! {
    struct StructOffsets {
        PyObject: struct {
            ob_type: i64
        },
        String: struct {
            data: i64,
            size: i64,
        },
        PyTypeObject: struct {
            tp_name: i64
        },
        PyThreadState: struct {
            next: i64,
            interp: i64,
            frame: i64,
            thread: i64,
        },
        PyInterpreterState: struct {
            tstate_head: i64,
        },
        PyRuntimeState: struct {
            interp_main: i64,
        },
        PyFrameObject: struct {
            f_back: i64,
            f_code: i64,
            f_lineno: i64,
            f_localsplus: i64,
        },
        PyCodeObject: struct {
            co_filename: i64,
            co_name: i64,
            co_varnames: i64,
            co_firstlineno: i64,
        },
        PyTupleObject: struct {
            ob_item: i64,
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

const PY27_OFFSETS: StructOffsets = StructOffsets {
    PyObject : PyObject {
        ob_type: 8
    },
    String: String{
        data: 36,                // offsetof(PyStringObject, ob_sval)
        size: 16,                // offsetof(PyVarObject, ob_size)
    },
    PyTypeObject: PyTypeObject{
        tp_name: 24
    },
    PyThreadState: PyThreadState{
        next: 0,
        interp: 8,
        frame: 16,
        thread: 144,
    },
    PyInterpreterState: PyInterpreterState{
        tstate_head: 8,
    },
    PyRuntimeState: PyRuntimeState{
        interp_main: -1, // N/A
    },
    PyFrameObject: PyFrameObject{
        f_back: 24,
        f_code: 32,
        f_lineno: 124,
        f_localsplus: 376,
    },
    PyCodeObject: PyCodeObject{
        co_filename: 80,
        co_name: 88,
        co_varnames: 56,
        co_firstlineno: 96,
    },
    PyTupleObject: PyTupleObject{
        ob_item: 24
    }
};

const PY36_OFFSETS: StructOffsets = StructOffsets {
    PyObject: PyObject{
        ob_type: 8
    },
    String: String{
        data: 48,                // sizeof(PyASCIIObject)
        size: 16,                // offsetof(PyVarObject, ob_size)
    },
    PyTypeObject: PyTypeObject{
        tp_name: 24
    },
    PyThreadState: PyThreadState{
        next: 8,
        interp: 16,
        frame: 24,
        thread: 152,
    },
    PyInterpreterState: PyInterpreterState{
        tstate_head: 8,
    },
    PyRuntimeState: PyRuntimeState{
        interp_main: -1, // N/A
    },
    PyFrameObject: PyFrameObject{
        f_back: 24,
        f_code: 32,
        f_lineno: 124,
        f_localsplus: 376,
    },
    PyCodeObject: PyCodeObject{
        co_filename: 96,
        co_name: 104,
        co_varnames: 64,
        co_firstlineno: 36,
    },
    PyTupleObject: PyTupleObject{
        ob_item: 24,
    }
};

const PY37_OFFSETS: StructOffsets = StructOffsets {
    PyObject: PyObject {
        ob_type: 8
    },
    String: String {
        data: 48,                // sizeof(PyASCIIObject)
        size: 16,                // offsetof(PyVarObject, ob_size)
    },
    PyTypeObject: PyTypeObject {
        tp_name: 24
    },
    PyThreadState: PyThreadState {
        next: 8,
        interp: 16,
        frame: 24,
        thread: 176,
    },
    PyInterpreterState: PyInterpreterState {
        tstate_head: 8,
    },
    PyRuntimeState: PyRuntimeState {
        interp_main: 32,
    },
    PyFrameObject: PyFrameObject {
        f_back: 24,
        f_code: 32,
        f_lineno: 108,
        f_localsplus: 360,
    },
    PyCodeObject: PyCodeObject {
        co_filename: 96,
        co_name: 104,
        co_varnames: 64,
        co_firstlineno: 36,
    },
    PyTupleObject: PyTupleObject {
        ob_item: 24,
    }
};

const PY38_OFFSETS: StructOffsets = StructOffsets {
    PyObject: PyObject {
        ob_type: 8
    },
    String: String {
        data: 48,                // sizeof(PyASCIIObject)
        size: 16,                // offsetof(PyVarObject, ob_size)
    },
    PyTypeObject: PyTypeObject {
        tp_name: 24
    },
    PyThreadState: PyThreadState {
        next: 8,
        interp: 16,
        frame: 24,
        thread: 176,
    },
    PyInterpreterState: PyInterpreterState {
        tstate_head: 8,
    },
    PyRuntimeState: PyRuntimeState {
        interp_main: 40,
    },
    PyFrameObject: PyFrameObject {
        f_back: 24,
        f_code: 32,
        f_lineno: 108,
        f_localsplus: 360,
    },
    PyCodeObject: PyCodeObject {
        co_filename: 104,
        co_name: 112,
        co_varnames: 72,
        co_firstlineno: 40,
    },
    PyTupleObject: PyTupleObject {
        ob_item: 24,
    }
};

const PY310_OFFSETS: StructOffsets = StructOffsets {
    PyObject: PyObject{
        ob_type: 8
    },
    String: String{
        data: 48,                // offsetof(PyStringObject, ob_sval)
        size: -1,                // offsetof(PyVarObject, ob_size)
    },
    PyTypeObject: PyTypeObject{
        tp_name: 24
    },
    PyThreadState: PyThreadState{
        next: 8,
        interp: 16,
        frame: 24,
        thread: 176,
    },
    PyInterpreterState: PyInterpreterState{
        tstate_head: 8,
    },
    PyRuntimeState: PyRuntimeState{
        interp_main: 40, // N/A
    },
    PyFrameObject: PyFrameObject {
        f_back: 24,
        f_code: 32,
        f_lineno: 100,
        f_localsplus: 352,
    },
    PyCodeObject: PyCodeObject {
        co_filename: 104,
        co_name: 112,
        co_varnames: 72,
        co_firstlineno: 40,
    },
    PyTupleObject: PyTupleObject {
        ob_item: 24
    },
};

// // List of mappings from Python 3 minor versions to offsets `get_offsets` depends on this list
// // being sorted in ascending order when it searches through it
// const std::vector<std::pair<version, struct_offsets>> python3Versions = {
//     {{3,6,0}, kPy36OffsetConfig},
//     {{3,7,0}, kPy37OffsetConfig},
//     {{3,8,0}, kPy38OffsetConfig},
//     // 39 is same as 38
//     {{3,10,0}, kPy310OffsetConfig},
// };

// const struct_offsets& get_offsets(version& version) {
//   if (versionmajor == 2) {
//     return kPy27OffsetConfig;
//   }
//   else {
//     // Find offsets for Python 3 version:
//     auto it = std::find_if(python3Versionscrbegin(), python3Versionscrend(), [&](auto item){
//       return itemfirst <= version;
//     });
//     return it->second;
//   }
// }
