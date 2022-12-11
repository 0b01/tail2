// This file contains the code and map definitions for the Python tracer

#undef asm_volatile_goto
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

#include "bpfdefs.h"
#include <linux/sched.h>
#include <linux/version.h>

#include "tracemgmt.h"
#include "types.h"
#include "tls.h"

// The number of Python frames to unwind per frame-unwinding eBPF program. If
// we start running out of instructions in the walk_python_stack program, one
// option is to adjust this number downwards.
#define FRAMES_PER_WALK_PYTHON_STACK 10

// Forward declaration to avoid warnings like
// "declaration of 'struct pt_regs' will not be visible outside of this function [-Wvisibility]".
struct pt_regs;

// Map from Python process IDs to a structure containing addresses of variables
// we require in order to build the stack trace
bpf_map_def SEC("maps/py_procs") py_procs = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(pid_t),
  .value_size = sizeof(PyProcInfo),
  .max_entries = 1024,
};

// Record a Python frame
static inline __attribute__((__always_inline__))
int push_python(Trace *trace, u64 file, u64 line) {
  return _push(trace, file, line, FRAME_MARKER_PYTHON);
}

static inline __attribute__((__always_inline__))
u64 py_encode_lineno(u32 object_id, u32 f_lasti) {
  return (object_id | (((u64)f_lasti) << 32));
}

static inline __attribute__((__always_inline__))
int process_python_frame(Trace *trace, PyProcInfo *pyinfo, const void *py_frameobject) {
  u64 lineno = FUNC_TYPE_UNKNOWN, file_id = UNKNOWN_FILE;
  u32 codeobject_id;

  // Vars used in extracting data from the Python interpreter
  void *py_codeobject;
  int py_f_lasti;
  int py_firstlineno;
  int py_flags;
  int py_argcount;
  int py_kwonlyargcount;

  // Get PyFrameObject->f_code
  if (bpf_probe_read(&py_codeobject, sizeof(void *),
                     py_frameobject + pyinfo->PyFrameObject_f_code)) {
    DEBUG_PRINT(
        "Failed to read PyFrameObject->f_code at 0x%lx",
        (unsigned long) (py_frameobject + pyinfo->PyFrameObject_f_code));
    increment_metric(metricID_UnwindPythonErrBadFrameCodeObjectAddr);
    return -1;
  }

  if (!py_codeobject) {
    DEBUG_PRINT(
        "Null codeobject for PyFrameObject 0x%lx 0x%lx",
        (unsigned long) py_frameobject,
        (unsigned long) (py_frameobject + pyinfo->PyFrameObject_f_code));
    increment_metric(metricID_UnwindPythonZeroFrameCodeObject);
    goto push_frame;
  }

  file_id = (u64)py_codeobject;

  // See experiments/python/README.md for a longer version of this. In short, we
  // cannot directly obtain the correct Python line number. It has to be calculated
  // using information found in the PyCodeObject for the current frame. This
  // calculation involves iterating over potentially unbounded data, and so we don't
  // want to do it in eBPF. Instead, we log the bytecode instruction that is being
  // executed, and then convert this to a line number in the user-land component.
  // Bytecode instructions are identified as an offset within a code object. The
  // offset is easy to retrieve (PyFrameObject->f_lasti). Code objects are a little
  // more tricky. We need to log enough information to uniquely identify the code
  // object for the current frame, so that in the user-land component we can load
  // it from the .pyc. There is no unique identifier for code objects though, so we
  // try to construct one below by hashing together a few fields. These fields are
  // selected in the *hope* that no collisions occur between code objects.

  // Get PyFrameObject->f_lasti
  if (bpf_probe_read(&py_f_lasti, sizeof(int),
                     py_frameobject + pyinfo->PyFrameObject_f_lasti)) {
    DEBUG_PRINT(
        "Failed to read PyFrameObject->f_lasti at 0x%lx",
        (unsigned long) (py_frameobject + pyinfo->PyFrameObject_f_lasti));
    increment_metric(metricID_UnwindPythonErrBadFrameLastInstructionAddr);
    return -1;
  }

  // Get PyCodeObject->co_argcount (for code object hash)
  if (bpf_probe_read(&py_argcount, sizeof(int),
                     py_codeobject + pyinfo->PyCodeObject_co_argcount)) {
    DEBUG_PRINT(
        "Failed to read PyCodeObject->co_argcount at 0x%lx",
        (unsigned long) (py_codeobject + pyinfo->PyCodeObject_co_argcount));
    increment_metric(metricID_UnwindPythonErrBadCodeObjectArgCountAddr);
    return -1;
  }

  // Get PyCodeObject->co_kwonlyargcount (for code object hash)
  if (bpf_probe_read(&py_kwonlyargcount, sizeof(int),
                     py_codeobject + pyinfo->PyCodeObject_co_kwonlyargcount)) {
    DEBUG_PRINT(
        "Failed to read PyCodeObject->co_kwonlyargcount at 0x%lx",
        (unsigned long) (py_codeobject + pyinfo->PyCodeObject_co_kwonlyargcount));
    increment_metric(metricID_UnwindPythonErrBadCodeObjectKWOnlyArgCountAddr);
    return -1;
  }

  // Get PyCodeObject->co_flags (for code object hash)
  if (bpf_probe_read(&py_flags, sizeof(int),
                     py_codeobject + pyinfo->PyCodeObject_co_flags)) {
    DEBUG_PRINT(
        "Failed to read PyCodeObject->co_flags at 0x%lx",
        (unsigned long) (py_codeobject + pyinfo->PyCodeObject_co_flags));
    increment_metric(metricID_UnwindPythonErrBadCodeObjectFlagsAddr);
    return -1;
  }

  // Get PyCodeObject->co_firstlineno (for code object hash)
  if (bpf_probe_read(&py_firstlineno, sizeof(int),
                     py_codeobject + pyinfo->PyCodeObject_co_firstlineno)) {
    DEBUG_PRINT(
        "Failed to read PyCodeObject->co_firstlineno at 0x%lx",
        (unsigned long) (py_codeobject + pyinfo->PyCodeObject_co_firstlineno));
    increment_metric(metricID_UnwindPythonErrBadCodeObjectFirstLineNumberAddr);
    return -1;
  }

  codeobject_id = hash32(py_firstlineno);
  codeobject_id += hash32(py_flags);
  codeobject_id += hash32(py_kwonlyargcount);
  codeobject_id += hash32(py_argcount);

  lineno = py_encode_lineno(codeobject_id, (u32)py_f_lasti);

push_frame:
  DEBUG_PRINT("Pushing Python %lx %lu", (unsigned long) file_id, (unsigned long) lineno);
  if (push_python(trace, file_id, lineno)) {
    DEBUG_PRINT("failed to push python frame");
    return -1;
  }
  return 0;
}

SEC("perf_event/walk_python_stack")
int walk_python_stack(struct pt_regs *ctx) {
  void *py_frame = 0;
  int unwinder = PROG_UNWIND_STOP;

  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  Trace *trace = &record->trace;
  pid_t pid = trace->pid;

  PyProcInfo *pyinfo = bpf_map_lookup_elem(&py_procs, &pid);
  if (!pyinfo)
    goto stop;

  py_frame = record->pythonUnwindState.py_frame;
  if (!py_frame)
    goto stop;


#pragma unroll
  for (u32 i = 0; i < FRAMES_PER_WALK_PYTHON_STACK; ++i) {
    if (process_python_frame(trace, pyinfo, py_frame)) {
      goto stop;
    }
    increment_metric(metricID_UnwindPythonFrames);

    // Get PyFrameObject->f_back
    if (bpf_probe_read(&py_frame, sizeof(void *),
                       py_frame + pyinfo->PyFrameObject_f_back)) {
      DEBUG_PRINT(
          "Failed to read PyFrameObject->f_back from 0x%lx",
          (unsigned long) (py_frame + pyinfo->PyFrameObject_f_back));
      increment_metric(metricID_UnwindPythonErrBadFrameObjectBackAddr);
      goto stop;
    }

    // If we lift this check to the loop condition then unrolling fails
    if (!py_frame || trace->stack_len >= MAX_FRAME_UNWINDS) {
      goto stop;
    }
  }

  // Set up the state for the next invocation of this unwinding program.
  record->pythonUnwindState.py_frame = py_frame;
  unwinder = PROG_WALK_PYTHON_STACK;

stop:
  bpf_tail_call(ctx, &progs, unwinder);
  DEBUG_PRINT("bpf_tail_call failed for %d", unwinder);
  return -1;
}

// get_PyThreadState retrieves the PyThreadState* for the current thread.
//
// Python sets the thread_state using pthread_setspecific with the key
// stored in a global variable autoTLSkey.
//
// Once the autoTLSkey is available we use it to read the value in the
// thread-local storage. This address calculation relies on pthread
// implementation. It is basically the same as running the following in GDB:
//  p *(PyThreadState*)((struct pthread*)pthread_self())->
//    specific_1stblock[autoTLSkey]->data
static inline __attribute__((__always_inline__))
int get_PyThreadState(PyProcInfo *pyinfo, void *tls_base, void *autoTLSkeyAddr, void **thread_state) {
  int key;
  if (bpf_probe_read(&key, sizeof(key), autoTLSkeyAddr)) {
    DEBUG_PRINT("Failed to read autoTLSkey from 0x%lx", (unsigned long) autoTLSkeyAddr);
    return -1;
  }
  return tls_read(tls_base, key, thread_state);
}

// unwind_python is the entry point for tracing when invoked from the native tracer
// or interpreter dispatcher. It does not reset the trace object and will append the
// Python stack frames to the trace object for the current CPU.
SEC("perf_event/unwind_python")
int unwind_python(struct pt_regs *ctx) {
  void *tstate_current;
  void *py_tls_thread_state;
  void *tls_base;

  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  Trace *trace = &record->trace;
  u32 pid = trace->pid;

  DEBUG_PRINT("unwind_python()");

  PyProcInfo *pyinfo = bpf_map_lookup_elem(&py_procs, &pid);
  if (!pyinfo) {
    // Not a Python process that we have info on
    DEBUG_PRINT("Can't build Python stack, no address info");
    return 0;
  }
  DEBUG_PRINT("Building Python stack for 0x%x", pyinfo->version);
  record->ha_symbolization_needed = true;

  increment_metric(metricID_UnwindPythonAttempts);

  // Get the current python thread holding the GIL
  if (bpf_probe_read(
          &tstate_current, sizeof(void *),
          (void *) pyinfo->tstateCurrentAddr)) {
    DEBUG_PRINT("Failed to get tstateCurrent from 0x%llx",
                pyinfo->tstateCurrentAddr);
    increment_metric(metricID_UnwindPythonErrBadPyThreadStateCurrentAddr);
    return -1;
  }

  if (tls_get_base(ctx, &tls_base)) {
    DEBUG_PRINT("Failed to get TLS base address");
    return -1;
  }
  DEBUG_PRINT("tstateCurrent 0x%lx, TLS Base 0x%lx, autoTLSKeyAddr 0x%lx",
      (unsigned long) tstate_current,
      (unsigned long) tls_base,
      (unsigned long) pyinfo->autoTLSKeyAddr);

  // Get the PyThreadState from TLS
  if (get_PyThreadState(pyinfo, tls_base, (void *) pyinfo->autoTLSKeyAddr,
          &py_tls_thread_state)) {
    return -1;
  }

  if(!py_tls_thread_state) {
    DEBUG_PRINT("PyThreadState is 0x0");
    increment_metric(metricID_UnwindPythonErrZeroThreadState);
    return -1;
  }


  // The PyThreadState* in _PyThreadState_Current represents the Python thread that
  // currently holds the GIL. If this PyThreadState* is the same one found in TLS
  // then the thread we are building a stack trace from holds the GIL. If they are
  // not equal then the thread we are building a stack trace from does not hold the
  // GIL. We make note of this as we would like to be able to differentiate a frame
  // appearing in a stack trace when it is actually running, versus blocked, as well
  // as being able to determine if there is a lot of GIL contention in a system.
  trace->python_gil_held = tstate_current == py_tls_thread_state;
  DEBUG_PRINT("tstateTLS 0x%lx, GIL held: %d",
      (unsigned long)py_tls_thread_state,
      (int)trace->python_gil_held);

  // Get PyThreadState.frame
  if (bpf_probe_read(
          &record->pythonUnwindState.py_frame, sizeof(void *),
          py_tls_thread_state + pyinfo->PyThreadState_frame)) {
    DEBUG_PRINT(
        "Failed to read PyThreadState.frame at 0x%lx",
        (unsigned long) (py_tls_thread_state + pyinfo->PyThreadState_frame));
    increment_metric(metricID_UnwindPythonErrBadThreadStateFrameAddr);
    return -1;
  }

  if (!record->pythonUnwindState.py_frame) {
    DEBUG_PRINT("PyThreadState.frame is 0x0");
    return 0;
  }

  bpf_tail_call(ctx, &progs, PROG_WALK_PYTHON_STACK);
  DEBUG_PRINT("bpf_tail_call failed for PROG_WALK_PYTHON_STACK");
  return -1;
}
