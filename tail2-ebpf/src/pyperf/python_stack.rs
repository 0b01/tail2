use core::{mem::{size_of, self}};

use aya_bpf::{BpfContext, helpers::{bpf_probe_read_user}, cty::c_void};
use aya_log_ebpf::info;
use tail2_common::python::{state::{PYTHON_STACK_FRAMES_PER_PROG, PythonSymbol, ErrorCode, CLASS_NAME_LEN, FILE_NAME_LEN}, offsets::PythonOffsets};

use super::SampleState;

pub unsafe fn read_python_stack<C: BpfContext>(ctx: &C, state: &mut SampleState, frame_ptr: usize) -> Result<(), ErrorCode> {
    // info!(ctx, "read_python_stack: {}", frame_ptr);
    let mut cur_frame = frame_ptr;
    for _ in 0..PYTHON_STACK_FRAMES_PER_PROG {
        // read PyCodeObject first, if that fails, then no point reading next frame
        let cur_code_ptr: usize = bpf_probe_read_user(((cur_frame + state.offsets.py_frame_object.f_code) as *const _)).unwrap_or_default();
        // read current PyFrameObject filename/name
        // The compiler substitutes a constant for `i` because the loop is unrolled. This guarantees we
        // are always within the array bounds. On the other hand, `stack_len` is a variable, so the
        // verifier can't guarantee it's within bounds without an explicit check.
        let mut sym = PythonSymbol::default();
        read_symbol(ctx, state, cur_frame, cur_code_ptr, &mut sym)?;
        // to please the verifier...
        // if (event->stack_len < STACK_MAX_LEN) {
        //     event->stack[event->stack_len++] = symbol_id;
        // }
    //     // read next PyFrameObject pointer, update in place
    //     bpf_probe_read_user(
    //         &state->frame_ptr, sizeof(state->frame_ptr),
    //         cur_frame + state->offsets.PyFrameObject.f_back);
    //     if (!state->frame_ptr) {
    //         goto complete;
    //     }
    }

    Ok(())
}

unsafe fn read<T>(ptr: usize) -> Result<T, ErrorCode> {
    bpf_probe_read_user(ptr as *const T).map_err(|_| ErrorCode::ERROR_READ_FRAME)
}


/// read_symbol_names in the original source
pub unsafe fn read_symbol<C: BpfContext>(ctx: &C, state: &mut SampleState, frame: usize, code_ptr: usize, sym: &mut PythonSymbol) -> Result<(), ErrorCode> {
    if (code_ptr == 0) {
        return Err(ErrorCode::ERROR_FRAME_CODE_IS_NULL);
    }
    sym.lineno = read(code_ptr + state.offsets.py_code_object.co_firstlineno)?;
    info!(ctx, "lineno: {}", sym.lineno);
    // get_classname(&state.offsets, frame, code_ptr, &mut sym.classname)?;
    let pystr_ptr: usize = read(code_ptr + state.offsets.py_code_object.co_filename)?;
    // TODO: too big for stack
    // sym.file = read(pystr_ptr + state.offsets.string.data)?;
    // aya_bpf::helpers::gen::bpf_probe_read_user(
    //     (&mut sym.file).as_mut_ptr() as *mut c_void,
    //     mem::size_of::<[u8; FILE_NAME_LEN]>() as u32,
    //     (pystr_ptr + state.offsets.string.data) as *const c_void,
    // );

    // read PyCodeObject's name into symbol
    let pystr_ptr: usize = read(code_ptr + state.offsets.py_code_object.co_name)?;
    sym.name = read(pystr_ptr + state.offsets.string.data)?;
    Ok(())
}

/// Read the name of the class wherein a code object is defined.
/// For global functions, sets an empty string.
unsafe fn get_classname(offsets: &PythonOffsets, cur_frame: usize, code_ptr: usize, class_name: &mut [u8; CLASS_NAME_LEN]) -> Result<(), ErrorCode> {
    // Figure out if we want to parse class name, basically checking the name of
    // the first argument. If it's 'self', we get the type and its name, if it's
    // 'cls', we just get the name. This is not perfect but there is no better way
    // to figure this out from the code object.
    let argname = get_first_arg_name(offsets, code_ptr)?;
    // compare strings as ints to save instructions
    let self_str = b"self";
    let cls_str = b"cls\0";
    let first_self = &argname == self_str;
    let first_cls = &argname == cls_str;
    if !first_self && !first_cls {
        return Err(ErrorCode::FIRST_ARG_NOT_FOUND);
    }
    // Read class name from $frame->f_localsplus[0]->ob_type->tp_name.
    // read f_localsplus[0]:
    let mut tmp: usize = read(cur_frame + offsets.py_frame_object.f_localsplus)?;
    if (tmp == 0) {
        // self/cls is a cellvar, deleted, or not an argument. tough luck :/
        return Err(ErrorCode::FIRST_ARG_NOT_FOUND);
    }
    if first_self {
        // we are working with an instance, first we need to get type
        tmp = read(tmp + offsets.py_object.ob_type)?;
    }

    *class_name = read(tmp + offsets.py_type_object.tp_name)?;
    Ok(())
}

/// Reads the name of the first argument of a PyCodeObject.
unsafe fn get_first_arg_name(offsets: &PythonOffsets, code_ptr: usize) -> Result<[u8; 4], ErrorCode> {
    // gdb:  ((PyTupleObject*)$frame->f_code->co_varnames)->ob_item[0]
    let args_ptr: usize = read(code_ptr + offsets.py_code_object.co_varnames)?;
    // String.size is PyVarObject.ob_size
    let ob_size: usize = read((args_ptr as i64 + offsets.string.size) as usize)?;
    if ob_size <= 0 {
        return Err(ErrorCode::ERROR_GET_FIRST_ARG);
    }
    let args_ptr: usize = read((args_ptr + offsets.py_tuple_object.ob_item) as usize)?;
    read(args_ptr + offsets.string.data)
}


// int read_python_stack(struct pt_regs* ctx) {
//   void *cur_frame;
//   void *cur_code_ptr;
// #pragma unroll


//   state->python_stack_prog_call_cnt++;
//   if (state->python_stack_prog_call_cnt < PYTHON_STACK_PROG_CNT) {
//     // read next batch of frames
//     progs.call(ctx, PYTHON_STACK_PROG_IDX);
//     event->error_code = ERROR_CALL_FAILED;
//     goto submit;
//   } else {
//     event->error_code = ERROR_NONE;
//     event->stack_status = STACK_STATUS_TRUNCATED;
//     goto submit;
//   }
// complete:
//   event->error_code = ERROR_NONE;
//   event->stack_status = STACK_STATUS_COMPLETE;
// submit:
//   events.perf_submit(ctx, &state->event, sizeof(struct event));
//   return 0;
// }