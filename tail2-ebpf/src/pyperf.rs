use aya_bpf::{maps::{ProgramArray, PerCpuArray, PerfEventArray, HashMap}, programs::PerfEventContext, macros::{perf_event, map}, helpers::{bpf_get_current_comm, bpf_probe_read_user, bpf_probe_read_kernel, bpf_get_current_task}, bindings::{BPF_F_REUSE_STACKID, task_struct}, BpfContext};
use aya_log_ebpf::info;
use tail2_common::python::{state::{PythonSymbol, Event, pid_data, StackStatus, ErrorCode, pthreads_impl}, offsets::PythonOffsets};

use crate::{PIDS, helpers::get_pid_tgid, KERNEL_STACKS};

struct SampleState {
    current_thread_id: u64,
    constant_buffer_addr: usize,
    interp_head: usize,
    thread_state: usize,
    offsets: PythonOffsets,
    cur_cpu: u32,
    symbol_counter: u32,
    get_thread_state_call_count: i32,
    frame_ptr: usize,
    python_stack_prog_call_cnt: i32,
    event: Event,
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
const CPU_BITS: u32 = 10;
const COUNTER_BITS: u32 = (31 - CPU_BITS);
const MAX_SYMBOLS: u32 = (1 << COUNTER_BITS);

#[map(name="py_symbols")]
static SYMBOLS: HashMap<PythonSymbol, i32> = HashMap::with_max_entries(32768/* TODO: configurable */, 0);

/// Contains fd's of get_thread_state and read_python_stack programs.
#[map]
static PROGS: ProgramArray = ProgramArray::with_max_entries(2, 0);

#[map]
static STATE_HEAP: PerCpuArray<SampleState> = PerCpuArray::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);


#[perf_event(name="pyperf")]
fn pyperf(ctx: PerfEventContext) -> Option<u32> {
    let result = pyperf_inner(&ctx);
    match result {
        Ok(v) => info!(&ctx, "ok: {}", v as usize),
        Err(e) => info!(&ctx, "err: {}", e as usize),
    }
    
    Some(0)
}

fn pyperf_inner<C: BpfContext>(ctx: &C) -> Result<u32, ErrorCode> {
    let task: *const _ = unsafe { bpf_get_current_task() as *const _ };
    let ns = get_pid_tgid();
    let proc_info = unsafe { &mut *PIDS.get_ptr_mut(&ns.pid).ok_or(ErrorCode::NO_PID)? };
    let pid_data = &mut proc_info.runtime_type.python_pid_data();

    let Some(buf_ptr) = STATE_HEAP.get_ptr_mut(0) else { return Err(ErrorCode::CANT_ALLOC); };
    let state = unsafe { &mut *buf_ptr };
    let event = &mut state.event;
    event.pid = ns.pid;
    event.tid = ns.tgid;
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    }

    // Initialize stack info
    if let Ok(stack_id) = unsafe { KERNEL_STACKS.get_stackid(ctx, BPF_F_REUSE_STACKID as u64) } {
        event.kernel_stack_id = stack_id;
    } else {
        event.kernel_stack_id = -1;
    }
    event.stack_len = 0;
    event.stack_status = StackStatus::STACK_STATUS_ERROR;
    event.error_code = ErrorCode::ERROR_NONE;

    let offsets = proc_info.runtime_type.python_version().offsets();

    if (pid_data.interp == 0) {
        // This is the first time we sample this process (or the GIL is still released).
        // Let's find PyInterpreterState:
        let interp_ptr = if pid_data.globals._PyRuntime != 0 {
            pid_data.globals._PyRuntime + offsets.py_runtime_state.interp_main
        } else {
            if pid_data.globals._PyThreadState_Current == 0 {
                return Err(ErrorCode::ERROR_MISSING_PYSTATE);
            }

            // Get PyThreadState of the thread that currently holds the GIL
            let _PyThreadState_Current: usize = unsafe {
                bpf_probe_read_user(pid_data.globals._PyThreadState_Current as *const _)
            }.unwrap();

            if _PyThreadState_Current == 0 {
                // The GIL is released, we can only get native stacks
                // until it is held again.
                // TODO: mark GIL state = released in event
                return Err(ErrorCode::ERROR_THREAD_STATE_NULL);
            }
            // Read the interpreter pointer from the ThreadState:
            _PyThreadState_Current + offsets.py_thread_state.interp
        };
        pid_data.interp = unsafe { bpf_probe_read_user(interp_ptr as *const _) }.map_err(|_|ErrorCode::ERROR_INTERPRETER_NULL)?;
        if pid_data.interp == 0 {
            return Err(ErrorCode::ERROR_INTERPRETER_NULL);
        }
    }
    state.current_thread_id = get_task_thread_id(task, pid_data.pthreads_impl)?;

    state.offsets = offsets;
    state.interp_head = pid_data.interp;
    state.constant_buffer_addr = pid_data.globals.constant_buffer;
    // Read pointer to first PyThreadState in thread states list:
    state.thread_state = unsafe { bpf_probe_read_user(
        (state.interp_head +
            offsets.py_interpreter_state.tstate_head) as *const _)}
        .map_err(|i| {info!(ctx, "{}", i); ErrorCode::ERROR_NONE} )? ;
    if (state.thread_state == 0) {
        return Err(ErrorCode::ERROR_THREAD_STATE_HEAD_NULL);
    }
    info!(ctx, "thread state: {}", state.thread_state);

    Ok(0)
}


/// Get the thread id for a task just as Python would. Currently assumes Python uses pthreads.
pub fn get_task_thread_id(task: *const task_struct, pthreads_impl: pthreads_impl) -> Result<u64, ErrorCode> {
    // The thread id that is written in the PyThreadState is the value of `pthread_self()`.
    // For glibc, corresponds to THREAD_SELF in "tls.h" in glibc source.
    // For musl, see definition of `__pthread_self`.
    // HACK: Usually BCC would translate a deref of the field into `read_kernel` for us, but it
    //       doesn't detect it due to the macro (because it transforms before preprocessing).
    let fs_offset = 0; // TODO: ?
    let fsbase: u64 = unsafe { bpf_probe_read_kernel((task as i64 + fs_offset) as *const _).unwrap() };
    let ret = match pthreads_impl {
        pthreads_impl::PTI_GLIBC => {
            // 0x10 = offsetof(tcbhead_t, self)
            unsafe { bpf_probe_read_user((fsbase + 0x10) as *const _).unwrap() }
        }
        pthreads_impl::PTI_MUSL => {
            unsafe { bpf_probe_read_user(fsbase as *const _).unwrap() }
        }
    };

    Ok(ret)
// if (ret < 0) {
//     return ERROR_BAD_FSBASE;
//   }
//   return ERROR_NONE;
}