use core::mem::{size_of, transmute};

use aya_bpf::{maps::{ProgramArray, PerCpuArray, PerfEventArray, HashMap}, programs::PerfEventContext, macros::{perf_event, map}, helpers::{bpf_get_current_comm, bpf_probe_read_user, bpf_probe_read_kernel, bpf_get_current_task, bpf_probe_read, bpf_get_smp_processor_id}, bindings::BPF_F_REUSE_STACKID, BpfContext, memset};
use aya_log_ebpf::{info, error};
use tail2_common::{python::{state::{PythonSymbol, PythonStack, pid_data, StackStatus, pthreads_impl}, offsets::PythonOffsets}, metrics::Metrics};
use crate::{vmlinux::task_struct, sample::PIDS};

use crate::{helpers::get_pid_tgid};

use super::{thread::{get_thread_state, get_task_thread_id}, python_stack::read_python_stack};

#[repr(C)]
pub struct SampleState {
    pub current_thread_id: u64,
    pub constant_buffer_addr: usize,
    pub interp_head: usize,
    pub thread_state: usize,
    pub cur_cpu: i32,
    pub symbol: PythonSymbol,
    pub get_thread_state_call_count: usize,
    pub python_stack_prog_call_cnt: usize,
}


// Hashtable of symbol to unique id.
// An id looks like this: |sign||cpu||counter|
// Where:
//  - sign (1 bit): 0 means a valid id. 1 means a negative error value.
//  - cpu (10 bits): the cpu on which this symbol was first encountered.
//  - counter (21 bits): per-cpu symbol sequential counter.
// Thus, the maximum amount of CPUs supported is 2^10 (=1024) and the maximum amount of symbols is
// 2^21 (~2M).
// See `get_symbol_id`.
const CPU_BITS: i32 = 10;
const COUNTER_BITS: i32 = (31 - CPU_BITS);
const MAX_SYMBOLS: i32 = (1 << COUNTER_BITS);

#[map(name="PY_SYMBOLS")]
static SYMBOLS: HashMap<PythonSymbol, i32> = HashMap::with_max_entries(32768/* TODO: configurable */, 0);

#[map]
static STATE_HEAP: PerCpuArray<SampleState> = PerCpuArray::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<PythonStack> = PerfEventArray::new(0);

#[inline(always)]
pub(crate) fn sample_python<C: BpfContext>(ctx: &C, stack: &mut PythonStack) -> Result<u32, Metrics> {
    let task: *const task_struct = unsafe { bpf_get_current_task() as *const _ };
    let ns = get_pid_tgid();
    let proc_info = unsafe { &mut *PIDS.get_ptr_mut(&ns.pid).ok_or(Metrics::ErrPy_NO_PID)? };

    if !proc_info.runtime_type.is_python() {
        return Err(Metrics::ErrPy_NOT_PYTHON);
    }

    let pid_data = &mut proc_info.runtime_type.python_pid_data();

    let Some(buf_ptr) = STATE_HEAP.get_ptr_mut(0) else { return Err(Metrics::ErrPy_CANT_ALLOC); };
    let state = unsafe { &mut *buf_ptr };
    if let Ok(comm) = bpf_get_current_comm() {
        stack.comm = comm;
    }

    stack.stack_status = StackStatus::STACK_STATUS_ERROR;
    stack.error_code = Metrics::ErrPy_NONE;

    let offsets = proc_info.runtime_type.python_version().offsets();

    if (pid_data.interp == 0) {
        // This is the first time we sample this process (or the GIL is still released).
        // Let's find PyInterpreterState:
        // tracing::info!(ctx, "interp_ptr: {}", pid_data.globals._PyRuntime);
        let interp_ptr = if pid_data.globals._PyRuntime != 0 {
            pid_data.globals._PyRuntime + offsets.py_runtime_state.interp_main
        } else {
            if pid_data.globals._PyThreadState_Current == 0 {
                return Err(Metrics::ErrPy_MISSING_PYSTATE);
            }

            // Get PyThreadState of the thread that currently holds the GIL
            let _PyThreadState_Current: usize = unsafe {
                bpf_probe_read_user(pid_data.globals._PyThreadState_Current as *const _)
            }.unwrap();

            if _PyThreadState_Current == 0 {
                // The GIL is released, we can only get native stacks
                // until it is held again.
                // TODO: mark GIL state = released in event
                return Err(Metrics::ErrPy_THREAD_STATE_NULL);
            }
            // Read the interpreter pointer from the ThreadState:
            _PyThreadState_Current + offsets.py_thread_state.interp
        };
        pid_data.interp = unsafe { bpf_probe_read_user(interp_ptr as *const _) }.map_err(|_|Metrics::ErrPy_INTERPRETER_NULL)?;
        if pid_data.interp == 0 {
            return Err(Metrics::ErrPy_INTERPRETER_NULL);
        }
    }

    state.current_thread_id = unsafe { get_task_thread_id(ctx, task, pid_data.pthreads_impl)? };

    state.interp_head = pid_data.interp;
    state.constant_buffer_addr = pid_data.globals.constant_buffer;
    // Read pointer to first PyThreadState in thread states list:
    state.thread_state = unsafe { bpf_probe_read_user(
        (state.interp_head +
            offsets.py_interpreter_state.tstate_head) as *const _)}
        .map_err(|i| {info!(ctx, "{}", i); Metrics::ErrPy_NONE} )? ;
    if (state.thread_state == 0) {
        return Err(Metrics::ErrPy_THREAD_STATE_HEAD_NULL);
    }

    // Call get_thread_state to find the PyThreadState of this thread:
    state.get_thread_state_call_count = 0;

    let frame_ptr = get_thread_state(ctx, state, &offsets)?;

    unsafe { read_python_stack(ctx, stack, state, &offsets, frame_ptr) };

    // event.error_code = Metrics::ErrPy_CALL_FAILED;
    // EVENTS.output(ctx, &state.event, 0);
    Ok(0)
}