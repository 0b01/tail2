use core::{mem::{size_of, self, transmute}};

use aya_bpf::{BpfContext, helpers::{bpf_probe_read_user}, cty::c_void, memset};
use aya_log_ebpf::info;
use tail2_common::python::{state::{PYTHON_STACK_FRAMES_PER_PROG, PythonSymbol, ErrorCode, CLASS_NAME_LEN, FILE_NAME_LEN, FRAME_MAX_LEN, PythonStack}, offsets::PythonOffsets};

use super::pyperf::SampleState;

#[inline(always)]
pub fn read_python_stack<C: BpfContext>(ctx: &C, stack: &mut PythonStack, state: &mut SampleState, offsets: &PythonOffsets, frame_ptr: usize) -> Result<(), ErrorCode> {
    let mut cur_frame = frame_ptr;
    stack.frames_len = 0;
    for _ in 0..PYTHON_STACK_FRAMES_PER_PROG {
        unsafe { read_symbol(ctx, &offsets, cur_frame, &mut state.symbol)? };
        if (stack.frames_len < FRAME_MAX_LEN) {
            stack.frames[stack.frames_len].copy(&mut state.symbol);
            stack.frames_len += 1;
        }

        // read next PyFrameObject pointer, update in place
        cur_frame = unsafe { read(cur_frame + offsets.py_frame_object.f_back)? };
        if cur_frame == 0 {
            break;
        }
    }

    Ok(())
}

#[inline(always)]
unsafe fn read<T>(ptr: usize) -> Result<T, ErrorCode> {
    bpf_probe_read_user(ptr as *const T).map_err(|_| ErrorCode::ERROR_READ_FRAME)
}

#[inline(always)]
/// read_symbol_names in the original source
pub unsafe fn read_symbol<C: BpfContext>(ctx: &C, offsets: &PythonOffsets, frame: usize, sym: &mut PythonSymbol) -> Result<(), ErrorCode> {
    let code_ptr: usize = read(frame + offsets.py_frame_object.f_code).unwrap_or_default();
    if (code_ptr == 0) {
        return Err(ErrorCode::ERROR_FRAME_CODE_IS_NULL);
    }
    sym.lineno = read(code_ptr + offsets.py_code_object.co_firstlineno)?;
    info!(ctx, "lineno: {}", sym.lineno);
    // get_classname(&offsets, frame, code_ptr, &mut sym.classname)?;
    let pystr_ptr: usize = read(code_ptr + offsets.py_code_object.co_filename)?;
    // TODO: too big for stack
    sym.file = [0; FILE_NAME_LEN];
    // sym.file = read(pystr_ptr + offsets.string.data)?;
    // aya_bpf::helpers::gen::bpf_probe_read_user(
    //     (&mut sym.file).as_mut_ptr() as *mut c_void,
    //     mem::size_of::<[u8; FILE_NAME_LEN]>() as u32,
    //     (pystr_ptr + offsets.string.data) as *const c_void,
    // );

    // read PyCodeObject's name into symbol
    let pystr_ptr: usize = read(code_ptr + offsets.py_code_object.co_name)?;
    sym.name = read(pystr_ptr + offsets.string.data)?;
    Ok(())
}

#[inline(always)]
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

#[inline(always)]
/// Reads the name of the first argument of a PyCodeObject.
unsafe fn get_first_arg_name(offsets: &PythonOffsets, code_ptr: usize) -> Result<[u8; 4], ErrorCode> {
    // gdb:  ((PyTupleObject*)$frame->f_code->co_varnames)->ob_item[0]
    let args_ptr: usize = read(code_ptr + offsets.py_code_object.co_varnames)?;
    // String.size is PyVarObject.ob_size
    // let ob_size: usize = read((args_ptr as i64 + offsets.string.size) as usize)?;
    // if ob_size <= 0 {
    //     return Err(ErrorCode::ERROR_GET_FIRST_ARG);
    // }
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