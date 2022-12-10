// This file contains the code and map definitions for the V8 tracer
//
// Core unwinding of frames is simple, as all the generated code uses frame pointers,
// and all the interesting data is directly accessible via FP. The only additional
// task needed in EBPF code is to collect the JSFunction* and potentially the current
// bytecode offset when in interpreted mode. Rest of the processing can be done from
// host agent.
//
// See the host agent interpreterv8.go for more references.

#undef asm_volatile_goto
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

#include "bpfdefs.h"
#include <linux/sched.h>
#include <linux/version.h>

#include "tracemgmt.h"
#include "types.h"
#include "tls.h"
#include "v8_tracer.h"

// The number of V8 frames to unwind per frame-unwinding eBPF program.
#define V8_FRAMES_PER_PROGRAM   10

// The maximum V8 frame length used in heuristic to validate FP
#define V8_MAX_FRAME_LENGTH     8192

// Map from V8 process IDs to a structure containing addresses of variables
// we require in order to build the stack trace
bpf_map_def SEC("maps/v8_procs") v8_procs = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(pid_t),
  .value_size = sizeof(V8ProcInfo),
  .max_entries = 1024,
};

// Record a V8 frame
static inline __attribute__((__always_inline__))
int push_v8(Trace *trace, unsigned long jsfunc, unsigned long delta_or_marker) {
  DEBUG_PRINT("Pushing v8 frame delta_or_marker=%lx, jsfunc=%lx", delta_or_marker, jsfunc);
  return _push(trace, jsfunc, delta_or_marker, FRAME_MARKER_V8);
}

// Read and verify a V8 tagged pointer from given memory location.
static inline __attribute__((__always_inline__))
uintptr_t v8_read_object_ptr(uintptr_t addr) {
  uintptr_t val;
  if (bpf_probe_read(&val, sizeof(val), (void*)addr)) {
    return 0;
  }
  if ((val & HeapObjectTagMask) != HeapObjectTag) {
    return 0;
  }
  return val & ~HeapObjectTagMask;
}

// Read, verify and parse a V8 SMI ("SMall Integer") from given memory location.
// On 64-bit systems: SMI is the upper 32-bits of a 64-bit word, and the lowest bit is the tag.
// Returns the SMI value, or def_value in case of errors.
static uintptr_t v8_read_smi(uintptr_t addr, uintptr_t def_value) {
  uintptr_t val;
  if (bpf_probe_read(&val, sizeof(val), (void*)addr)) {
    return def_value;
  }
  if ((val & SmiTagMask) != SmiTag) {
    return def_value;
  }
  return val >> SmiValueShift;
}

// Read the type tag of a Heap Object at given memory location.
// Returns zero on error (valid object type IDs are non-zero).
static u16 v8_read_object_type(V8ProcInfo *vi, uintptr_t addr) {
  if (!addr) {
    return 0;
  }
  uintptr_t map = v8_read_object_ptr(addr + vi->off_HeapObject_map);
  u16 type;
  if (!map || bpf_probe_read(&type, sizeof(type), (void*)(map + vi->off_Map_instancetype))) {
    return 0;
  }
  return type;
}

// Unwind one V8 frame
static int unwind_one_v8_frame(PerCPURecord *record, V8ProcInfo *vi, bool top) {
  UnwindState *state = &record->state;
  Trace *trace = &record->trace;
  unsigned long regs[2], sp = state->sp, fp = state->fp, pc = state->pc;

  // All V8 frames have frame pointer. Check that the FP looks valid.
  DEBUG_PRINT("v8: pc: %lx, sp: %lx, fp: %lx", pc, sp, fp);
  if (fp < sp || fp >= sp + V8_MAX_FRAME_LENGTH) {
    DEBUG_PRINT("v8: frame pointer too far off %lx / %lx", fp, sp);
    increment_metric(metricID_UnwindV8ErrBadFP);
    return -1;
  }

  // Data that will be sent to HA is in these variables.
  uintptr_t jsfunc = 0, delta_or_marker = 0;

  // Read the frame type marker
  if (bpf_probe_read(&delta_or_marker, sizeof(delta_or_marker), (void*)(fp + vi->off_fp_marker))) {
    DEBUG_PRINT("v8:  -> failed to read fp_marker");
    increment_metric(metricID_UnwindV8ErrBadFP);
    return -1;
  }
  // Before V8 5.8.261 the frame marker was a SMI. Now it has the tag, but it's not shifted fully.
  // The special coding was done to reduce the frame marker push <immed64> to <immed32>.
  if ((delta_or_marker & SmiTagMask) == SmiTag) {
    // Shift with the tag length only (shift on normal SMI is different).
    delta_or_marker >>= SmiTagShift;
    DEBUG_PRINT("v8:  -> stub frame, tag %ld", delta_or_marker);
    goto frame_done;
  }
  delta_or_marker = 0;

  // Extract the JSFunction being executed
  jsfunc = v8_read_object_ptr(fp + vi->off_fp_function);
  if (v8_read_object_type(vi, jsfunc) != vi->type_JSFunction) {
    DEBUG_PRINT("v8:  -> not a JSFunction");
    increment_metric(metricID_UnwindV8ErrBadJSFunc);
    return -1;
  }

  // And chase Code object from the function
  uintptr_t code = v8_read_object_ptr(jsfunc + vi->off_JSFunction_code);
  u16 code_type = v8_read_object_type(vi, code);
  if (code_type != vi->type_Code) {
    // If the object type tag does not match, it might be some new functionality
    // in the VM. Report the JSFunction for function name, but report no line
    // number information. This allows to get a complete trace even if this one
    // frame will have some missing information.
    DEBUG_PRINT("v8: func = %lx / code_type = %x", jsfunc, code_type);
    increment_metric(metricID_UnwindV8ErrBadCode);
    goto frame_done;
  }

  // Read the Code blob type and size
  uintptr_t code_start = code + vi->off_Code_instruction_start;
  u32 code_size;
  if (bpf_probe_read(&code_size, sizeof(code_size), (void*)(code + vi->off_Code_instruction_size))) {
    increment_metric(metricID_UnwindV8ErrBadCode);
    return -1;
  }

  uintptr_t code_end = code_start + code_size;
  DEBUG_PRINT("v8: func = %lx / code = %lx", jsfunc, code);
  DEBUG_PRINT("v8:  -> instructions: %lx..%lx (%d)", code_start, code_end, code_size);

  // The simplest way to check if we are in interpreter mode is to see if the
  // assumed BytecodeArray* is pointing to a such object.
  uintptr_t bytecode_array = v8_read_object_ptr(fp + vi->off_fp_bytecode_array);
  u16 bytecode_array_type = v8_read_object_type(vi, bytecode_array);
  DEBUG_PRINT("v8:  -> bca type: %x (expect %x) @%lx",
    (unsigned)bytecode_array_type, (unsigned)vi->type_BytecodeArray, bytecode_array);
  if (bytecode_array_type == vi->type_BytecodeArray) {
    // Bytecode is being used. Get the raw bytecode offset for the HA.
    delta_or_marker = v8_read_smi(fp + vi->off_fp_bytecode_offset, 0);
    DEBUG_PRINT("v8:  -> bytecode_delta %lx", delta_or_marker);
    goto frame_done;
  }

  // Mark this as native frame for the HA.
  jsfunc |= V8_FILE_FLAG_NATIVE;

  if (!(pc >= code_start && pc < code_end)) {
    // PC is not inside the Code object's code area. This should happen only
    // on top frame when we are executing prologue/epilogue of called function
    // and the frame pointer is pointing to the caller's frame.
    // Try to recover the original PC from the stack.
    if (top && trace->stack_len == 0) {
      unsigned long stk[3];
      if (bpf_probe_read(stk, sizeof(stk), (void*)(sp - sizeof(stk)))) {
        DEBUG_PRINT("v8:  --> bad stack pointer");
        increment_metric(metricID_UnwindV8ErrBadFP);
        return -1;
      }

      int i;
#pragma unroll
      for (i = sizeof(stk)/sizeof(stk[0])-1; i >= 0; i--) {
        if (stk[i] >= code_start && stk[i] < code_end) {
          break;
        }
      }
      if (i < 0) {
        // Not able to recover PC.
        // TODO: investigate why this seems to happen occasionally
        DEBUG_PRINT("v8:  --> outside code blob: stack top %lx %lx %lx",
          stk[2], stk[1], stk[0]);
        goto frame_done;
      }

      // Recover the PC for the function which is in FP.
      pc = stk[i];
      DEBUG_PRINT("v8:  --> pc recovered from stack: %lx", pc);
    } else {
      DEBUG_PRINT("v8:  --> outside code blob (not topmost frame)");
      goto frame_done;
    }
  }

  // Calculate PC delta for HA
  delta_or_marker = pc - code_start;

  // And store the code object pointer's significant bits as a cookie which
  // HA can use to determine if it needs refreshing. The cookie is not validated,
  // the HA will just trigger object reload if the cached cookie does not match
  // sent cookie.
  delta_or_marker |= (code >> 4) << V8_LINE_COOKIE_SHIFT;

frame_done:
  // Unwind with frame pointer
  if (bpf_probe_read(regs, sizeof(regs), (void*)fp)) {
    DEBUG_PRINT("v8:  --> bad frame pointer");
    increment_metric(metricID_UnwindV8ErrBadFP);
    return -1;
  }
  state->sp = fp + sizeof(regs);
  state->fp = regs[0];
  state->pc = regs[1];
  push_v8(trace, jsfunc, delta_or_marker);
  DEBUG_PRINT("v8: pc: %lx, sp: %lx, fp: %lx",
              (unsigned long) state->pc, (unsigned long) state->sp,
              (unsigned long) state->fp);

  increment_metric(metricID_UnwindV8Frames);
  return 0;
}

// unwind_v8 is the entry point for tracing when invoked from the native tracer
// or interpreter dispatcher. It does not reset the trace object and will append the
// V8 stack frames to the trace object for the current CPU.
SEC("perf_event/unwind_v8")
int unwind_v8(struct bpf_perf_event_data *ctx) {
  PerCPURecord *record = get_per_cpu_record();
  if (!record) {
    return -1;
  }

  Trace *trace = &record->trace;
  u32 pid = trace->pid;
  DEBUG_PRINT("==== unwind_v8 %d ====", trace->stack_len);

  V8ProcInfo *vi = bpf_map_lookup_elem(&v8_procs, &pid);
  if (!vi) {
    DEBUG_PRINT("v8: no V8ProcInfo for this pid");
    return 0;
  }

  record->ha_symbolization_needed = true;
  increment_metric(metricID_UnwindV8Attempts);

  int unwinder = PROG_UNWIND_STOP;
#pragma unroll
  for (int i = 0; i < V8_FRAMES_PER_PROGRAM; i++) {
    unwinder = PROG_UNWIND_STOP;
    if (unwind_one_v8_frame(record, vi, i == 0) != -1) {
      unwinder = get_next_unwinder(record);
    }
    if (unwinder != PROG_UNWIND_V8) {
      break;
    }
  }

  bpf_tail_call(ctx, &progs, unwinder);
  DEBUG_PRINT("v8: tail call for next frame unwinder (%d) failed", unwinder);
  return -1;
}
