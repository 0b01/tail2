// This file contains the code and map definitions for the PHP tracer

#undef asm_volatile_goto
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// The number of PHP frames to unwind per frame-unwinding eBPF program. If
// we start running out of instructions in the walk_php_stack program, one
// option is to adjust this number downwards.
#define FRAMES_PER_WALK_PHP_STACK 20

// PHP_FRAMES_HANDLED is a marker value to indicate that all PHP frames have
// been now processed.
#define PHP_FRAMES_HANDLED ((void*)-1)

// The type_info flag for executor data to indicate top-of-stack frames
// as defined in php/Zend/zend_compile.h.
#define ZEND_CALL_TOP (1 << 17)

// zend_function.type values we need from php/Zend/zend_compile.h
#define ZEND_USER_FUNCTION 2
#define ZEND_EVAL_CODE     4

// Map from PHP process IDs to the address of the `executor_globals` for that process
bpf_map_def SEC("maps/php_procs") php_procs = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(pid_t),
  .value_size = sizeof(PHPProcInfo),
  .max_entries = 1024,
};


// Map from PHP JIT process IDs to the address range of the `dasmBuf` for that process
bpf_map_def SEC("maps/php_jit_procs") php_jit_procs = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(pid_t),
  .value_size = sizeof(PHPJITProcInfo),
  .max_entries = 1024,
};

// Record a PHP frame
static inline __attribute__((__always_inline__))
int push_php(Trace *trace, u64 file, u64 line) {
  return _push(trace, file, line, FRAME_MARKER_PHP);
}

// Record a PHP call for which no function object is available
static inline __attribute__((__always_inline__))
int push_unknown_php(Trace *trace) {
  return _push(trace, UNKNOWN_FILE, FUNC_TYPE_UNKNOWN, FRAME_MARKER_PHP);
}

// Returns > 0 if `func` is inside the JIT buffer and 0 otherwise.
static inline __attribute__((__always_inline__))
int is_jit_function(u64 func, PHPJITProcInfo* jitinfo) {
  return func >= jitinfo->start && func < jitinfo->end;
}

static inline __attribute__((__always_inline__))
int process_php_frame(PerCPURecord *record, PHPProcInfo *phpinfo, const void *execute_data, u32 *type_info) {
  Trace *trace = &record->trace;

  // Get current_execute_data->func
  void *zend_function;
  if (bpf_probe_read(&zend_function, sizeof(void *), execute_data + phpinfo->zend_execute_data_function)) {
    DEBUG_PRINT("Failed to read current_execute_data->func (0x%lx)",
        (unsigned long) (execute_data + phpinfo->zend_execute_data_function));
    return metricID_UnwindPHPErrBadZendExecuteData;
  }

  // It is possible there is no function object.
  if (!zend_function) {
    if (push_unknown_php(trace)) {
      DEBUG_PRINT("failed to push unknown php frame");
      return -1;
    }
    return metricID_UnwindPHPFrames;
  }

  // Get zend_function->type
  u8 func_type;
  if (bpf_probe_read(&func_type, sizeof(func_type), zend_function + phpinfo->zend_function_type)) {
    DEBUG_PRINT("Failed to read execute_data->func->type (0x%lx)",
        (unsigned long) zend_function);
    return metricID_UnwindPHPErrBadZendFunction;
  }

  u32 lineno = 0;
  if (func_type == ZEND_USER_FUNCTION || func_type == ZEND_EVAL_CODE) {
    // Get execute_data->opline
    void *zend_op;
    if (bpf_probe_read(&zend_op, sizeof(void *), execute_data + phpinfo->zend_execute_data_opline)) {
      DEBUG_PRINT("Failed to read execute_data->opline (0x%lx)",
          (unsigned long) (execute_data + phpinfo->zend_execute_data_opline));
      return metricID_UnwindPHPErrBadZendExecuteData;
    }

    // Get opline->lineno
    if (bpf_probe_read(&lineno, sizeof(u32), zend_op + phpinfo->zend_op_lineno)) {
      DEBUG_PRINT("Failed to read executor_globals->opline->lineno (0x%lx)",
          (unsigned long) (zend_op + phpinfo->zend_op_lineno));
      return metricID_UnwindPHPErrBadZendOpline;
    }

    // Get execute_data->This.type_info. This reads into the `type_info` argument
    // so we can re-use it in walk_php_stack
    if(bpf_probe_read(type_info, sizeof(u32), execute_data + phpinfo->zend_execute_data_this_type_info)) {
      DEBUG_PRINT("Failed to read execute_data->This.type_info (0x%lx)",
                  (unsigned long) execute_data);
      return metricID_UnwindPHPErrBadZendExecuteData;
    }
  }

  // To give more information to the HA we also pass up the type info. This is safe
  // because lineno is 32-bits too.
  u64 lineno_and_type_info = ((u64)*type_info) << 32 | lineno;
  
  DEBUG_PRINT("Pushing PHP 0x%lx %u", (unsigned long) zend_function, lineno);
  if (push_php(trace, (u64) zend_function, lineno_and_type_info)) {
    DEBUG_PRINT("failed to push php frame");
    return -1;
  }

  return metricID_UnwindPHPFrames;
}

static inline __attribute__((__always_inline__))
int walk_php_stack(PerCPURecord *record, PHPProcInfo *phpinfo, PHPJITProcInfo* jitinfo) {
  const void *execute_data = record->phpUnwindState.zend_execute_data;
  bool mixed_traces = record->next_unwinder != PROG_UNWIND_STOP;

  // If PHP data is not available, all frames have been processed, then
  // continue with native unwinding.
  if (!execute_data || execute_data == PHP_FRAMES_HANDLED) {
    return record->next_unwinder;
  }

  int unwinder = PROG_UNWIND_PHP;
  u32 type_info = 0;
#pragma unroll
  for (u32 i = 0; i < FRAMES_PER_WALK_PHP_STACK; ++i) {
    int metric = process_php_frame(record, phpinfo, execute_data, &type_info);
    if (metric >= 0) {
      increment_metric(metric);
    }
    if (metric != metricID_UnwindPHPFrames) {
      goto err;
    }
    
    // Get current_execute_data->prev_execute_data
    if (bpf_probe_read(&execute_data, sizeof(void *),
            execute_data + phpinfo->zend_execute_data_prev_execute_data)) {
      DEBUG_PRINT("Failed to read current_execute_data->prev_execute_data (0x%lx)",
                  (unsigned long) execute_data);
      increment_metric(metricID_UnwindPHPErrBadZendExecuteData);
      goto err;
    }

    // Check end-of-stack and end of current interpreter loop stack conditions
    if (!execute_data || (mixed_traces && (type_info & ZEND_CALL_TOP))) {
      DEBUG_PRINT("Top-of-stack, with next execute_data=0x%lx", (unsigned long) execute_data);
      // JIT'd PHP code needs special support for recovering the return address on both amd64
      // and arm.
      // Essentially we have two cases here:
      // 1) The PC corresponds to something in the interpreter loop. We have stack
      //    deltas for this, so we don't need to do anything.
      // 2) The PC corresponds to something in the JIT region. We don't have stack
      //    deltas for this, so we need to use the previously recovered address.
      //    This previously recovered return address corresponds to an address inside
      //    "execute_ex" (the PHP interpreter loop). In particular, the asm looks like this:
      //    jmp [r15]
      //    mov rax, imm <==== This is the return address we previously recovered
      //    This approach only works because the address we're using here is inside the
      //    interpreter loop and on the same native stack frame: otherwise we'd need to
      //    get the next unwinder instead. 
      // This is only necessary when it's the last function because walking the PHP
      // stack is enough for the other functions. 
      if (jitinfo && is_jit_function(record->state.pc,jitinfo)) {
        record->state.pc = phpinfo->jit_return_address;
        unwinder = resolve_unwind_mapping(record);
      } else {
        unwinder = record->next_unwinder;
      }
      break;
    }
  }


  if (!execute_data) {
  err:
    execute_data = PHP_FRAMES_HANDLED;
  }
  record->phpUnwindState.zend_execute_data = execute_data;
  return unwinder;
}

SEC("perf_event/unwind_php")
int unwind_php(struct pt_regs *ctx) {
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  int unwinder = record->next_unwinder;
  u32 pid = record->trace.pid;
  PHPProcInfo *phpinfo = bpf_map_lookup_elem(&php_procs, &pid);
  if (!phpinfo) {
    DEBUG_PRINT("No PHP introspection data");
    goto exit;
  }

  increment_metric(metricID_UnwindPHPAttempts);

  if (!record->phpUnwindState.zend_execute_data) {
    // Get executor_globals.current_execute_data
    if (bpf_probe_read(&record->phpUnwindState.zend_execute_data, sizeof(void *),
                       (void*) phpinfo->current_execute_data)) {
      DEBUG_PRINT("Failed to read executor_globals.current_execute data (0x%lx)",
          (unsigned long) phpinfo->current_execute_data);
      increment_metric(metricID_UnwindPHPErrBadCurrentExecuteData);
      goto exit;
    }
  }

  // Check whether the PHP process has an enabled JIT
  PHPJITProcInfo *jitinfo = bpf_map_lookup_elem(&php_jit_procs, &pid);
  if(!jitinfo) {
    DEBUG_PRINT("No PHP JIT introspection data");
  }
  
#if defined(__aarch64__)
  // On ARM we need to adjust the stack pointer if we entered from JIT code
  // This is only a problem on ARM where the SP/FP are used for unwinding.
  // This is necessary because:
  // a) The PHP VM jumps into code by default. This is equivalent to having an inner frame.
  // b) The PHP VM allocates some space for alignment purposes and saving registers.
  // c) The amount and alignment of this space can change in hard-to-detect ways.
  // Given that there's no guarantess that anything pushed to the stack is useful we
  // simply ignore it. There may be a return address in some modes, but this is hard to detect
  // consistently.
  if(jitinfo && is_jit_function(record->state.pc, jitinfo)) {
      record->state.sp = record->state.fp;
  }
#endif
  
  DEBUG_PRINT("Building PHP stack (execute_data = 0x%lx)", (unsigned long) record->phpUnwindState.zend_execute_data);
  record->ha_symbolization_needed = true;

  // Unwind one call stack or unrolled length, and continue
  unwinder = walk_php_stack(record, phpinfo, jitinfo);

exit:
  bpf_tail_call(ctx, &progs, unwinder);
  return -1;
}
