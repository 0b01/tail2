use aya_bpf::{helpers::{bpf_probe_read_user, bpf_probe_read, bpf_get_smp_processor_id}, BpfContext};
use aya_log_ebpf::{info, error};
use tail2_common::{python::{state::pthreads_impl, offsets::PythonOffsets}, metrics::Metrics};

use crate::vmlinux::task_struct;

use super::pyperf::SampleState;

const THREAD_STATES_PER_PROG: usize = 32;
const THREAD_STATES_PROG_CNT: usize = 8;

#[inline(always)]
/// Searches through all the PyThreadStates in the interpreter to find the one
/// corresponding to the current task. Once found, call `read_python_stack`.
/// 
/// returns a frame_ptr
pub fn get_thread_state<C: BpfContext>(ctx: &C, state: &mut SampleState, offsets: &PythonOffsets) -> Result<usize, Metrics> {
    for i in 0..THREAD_STATES_PROG_CNT {
        let mut found = false;
        for i in 0..THREAD_STATES_PER_PROG {
            // Read the PyThreadState::thread_id to which this PyThreadState belongs:
            let thread_id = unsafe { bpf_probe_read_user((state.thread_state + offsets.py_thread_state.thread) as *const u64) };
            match thread_id {
                Ok(id) => {
                    // info!(ctx, "{} ?= {}", id, state.current_thread_id);
                    // if id == state.current_thread_id {
                    if id != state.current_thread_id { // Temp debug
                        found = true;
                        break;
                    } else {
                        // Read next thread state:
                        state.thread_state = unsafe { bpf_probe_read_user((state.thread_state + offsets.py_thread_state.next) as *const _).unwrap_or_default() };
                        if (state.thread_state == 0) {
                            error!(ctx, "not found");
                            return Err(Metrics::ErrPy_BAD_THREAD_STATE);
                        }

                    }
                }
                Err(e) => {
                    error!(ctx, "unable to read thread_id: {}", e);
                    return Err(Metrics::ErrPy_BAD_THREAD_STATE);
                }
            }
        }

        if found {
            break
        }

        if i == THREAD_STATES_PROG_CNT {
            return Err(Metrics::ErrPy_TOO_MANY_THREADS);
        }
    }

    // Get pointer to top frame from PyThreadState
    let frame_ptr = unsafe { bpf_probe_read_user( (state.thread_state + offsets.py_thread_state.frame) as *const _) };
    match frame_ptr {
        Ok(0) | Err(_) => Err(Metrics::ErrPy_EMPTY_STACK),
        Ok(f) => Ok(f),
    }

    // // We are going to need this later
    // state.cur_cpu = unsafe { bpf_get_smp_processor_id() };
    // info!(ctx, "found");
}

/// Get the thread id for a task just as Python would. Currently assumes Python uses pthreads.
pub unsafe fn get_task_thread_id<C: BpfContext>(ctx: &C, task: *const task_struct, pthreads_impl: pthreads_impl) -> Result<u64, Metrics> {
    // The thread id that is written in the PyThreadState is the value of `pthread_self()`.
    // For glibc, corresponds to THREAD_SELF in "tls.h" in glibc source.
    // For musl, see definition of `__pthread_self`.
    // HACK: Usually BCC would translate a deref of the field into `read_kernel` for us, but it
    //       doesn't detect it due to the macro (because it transforms before preprocessing).
    let fsbase = bpf_probe_read(&(*task).thread.uw.tp_value).unwrap();
    // info!(ctx, "fsbase: {}", fsbase);
    let ret = match pthreads_impl {
        pthreads_impl::PTI_GLIBC => {
            // 0x10 = offsetof(tcbhead_t, self)
            bpf_probe_read((fsbase + 0x310 + 0x18) as *const _).unwrap_or(902)
        }
        pthreads_impl::PTI_MUSL => {
            bpf_probe_read_user(fsbase as *const _).unwrap_or(903)
        }
    };
    // info!(ctx, "ret: {}", ret);
    Ok(ret)

    // Ok(ret)
// if (ret < 0) {
//     return ERROR_BAD_FSBASE;
//   }
//   return ERROR_NONE;
}