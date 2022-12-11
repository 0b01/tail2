// Provides type definitions shared by the eBPF and Go components

#ifndef OPTI_TYPES_H
#define OPTI_TYPES_H

#include <asm/types.h>
#include <stdbool.h>
#include "inttypes.h"

// ID values used as index to maps/metrics array.
// If you add enums below please update the following places too:
//  - The host agent ebpf metricID to DB IDMetric translation table in:
//    pf-host-agent/ebpf/ebpf.go/(StartMapMonitors).
//  - The ebpf userland test code metricID stringification table in:
//    pf-host-agent/support/ebpf/tests/tostring.c
enum {
  // number of calls to interpreter unwinding in get_next_interpreter()
  metricID_UnwindCallInterpreter = 0,

  // number of failures to call interpreter unwinding. Currently no longer used.
  metricID_UnwindErrCallInterpreter,

  // number of failures due to PC == 0 in unwind_next_frame()
  metricID_UnwindErrZeroPC,

  // number of times MAX_STACK_LEN has been exceeded
  metricID_UnwindErrStackLengthExceeded,

  // number of failures to read the TLS address
  metricID_UnwindErrBadTLSAddr,

  // number of failures to read the TLS base in get_tls_base()
  metricID_UnwindErrBadTPBaseAddr,

  // number of attempted unwinds
  metricID_UnwindNativeAttempts,

  // number of unwound frames
  metricID_UnwindNativeFrames,

  // number of native unwinds successfully ending with a stop delta
  metricID_UnwindNativeStackDeltaStop,

  // number of failures to look up ranges for text section in get_stack_delta()
  metricID_UnwindNativeErrLookupTextSection,

  // number of failed range searches within 20 steps in get_stack_delta()
  metricID_UnwindNativeErrLookupIterations,

  // number of failures to get StackUnwindInfo from stack delta map in get_stack_delta()
  metricID_UnwindNativeErrLookupRange,

  // number of kernel addresses passed to get_text_section()
  metricID_UnwindNativeErrKernelAddress,

  // number of failures to find the text section in get_text_section()
  metricID_UnwindNativeErrWrongTextSection,

  // number of failures due to no text section ID for PC in unwind_native()
  metricID_UnwindNativeErrNoTextForPC,

  // number of invalid stack deltas in the native unwinder
  metricID_UnwindNativeErrStackDeltaInvalid,

  // number of failures to read PC from stack
  metricID_UnwindNativeErrPCRead,

  // number of attempted perl unwinds
  metricID_UnwindPerlAttempts,

  // number of perl frames unwound
  metricID_UnwindPerlFrames,

  // number of failures to read perl TLS info
  metricID_UnwindPerlTLS,

  // number of failures to read perl stack info
  metricID_UnwindPerlReadStackInfo,

  // number of failures to read perl context stack entry
  metricID_UnwindPerlReadContextStackEntry,

  // number of failures to resolve perl EGV
  metricID_UnwindPerlResolveEGV,

  // number of attempted python unwinds
  metricID_UnwindPythonAttempts,

  // number of unwound python frames
  metricID_UnwindPythonFrames,

  // number of failures to read from pyinfo->pyThreadStateCurrentAddr
  metricID_UnwindPythonErrBadPyThreadStateCurrentAddr,

  // number of PyThreadState being 0x0
  metricID_UnwindPythonErrZeroThreadState,

  // number of failures to read the autoTLSkey address
  metricID_UnwindPythonErrBadAutoTLSKeyAddr,

  // number of failures to read PyThreadState.frame in unwind_python()
  metricID_UnwindPythonErrBadThreadStateFrameAddr,

  // number of failures to read PyFrameObject->f_back in walk_python_stack()
  metricID_UnwindPythonErrBadFrameObjectBackAddr,

  // number of failures to read PyFrameObject->f_code in process_python_frame()
  metricID_UnwindPythonErrBadFrameCodeObjectAddr,

  // number of NULL code objects found in process_python_frame()
  metricID_UnwindPythonZeroFrameCodeObject,

  // number of code objects with no filename in process_python_frame()
  metricID_UnwindPythonErrBadCodeObjectFilenameAddr,

  // number of failures to zero out filename in process_python_frame()
  metricID_UnwindPythonErrBadZeroFileAddr,

  // number of failures to zero out filename in process_python_frame()
  metricID_UnwindPythonErrBadFilenameAddr,

  // number of failures to get the file ID in process_python_frame()
  metricID_UnwindPythonErrNoFileID,

  // number of failures to get the last instruction address in process_python_frame()
  metricID_UnwindPythonErrBadFrameLastInstructionAddr,

  // number of failures to get code object's argcount in process_python_frame()
  metricID_UnwindPythonErrBadCodeObjectArgCountAddr,

  // number of failures to get code object's kwonlyargcount in process_python_frame()
  metricID_UnwindPythonErrBadCodeObjectKWOnlyArgCountAddr,

  // number of failures to get code object's flags in process_python_frame()
  metricID_UnwindPythonErrBadCodeObjectFlagsAddr,

  // number of failures to get code object's first line number in process_python_frame()
  metricID_UnwindPythonErrBadCodeObjectFirstLineNumberAddr,

  // number of attempted PHP unwinds
  metricID_UnwindPHPAttempts,

  // number of unwound PHP frames
  metricID_UnwindPHPFrames,

  // number of failures to read PHP current execute data pointer
  metricID_UnwindPHPErrBadCurrentExecuteData,

  // number of failures to read PHP execute data contents
  metricID_UnwindPHPErrBadZendExecuteData,

  // number of failures to read PHP zend function contents
  metricID_UnwindPHPErrBadZendFunction,

  // number of failures to read PHP zend opline contents
  metricID_UnwindPHPErrBadZendOpline,

  // number of failures to create hash for a trace in update_trace_count()
  metricID_ErrHashTrace,

  // number of failures to report new frames
  metricID_ErrReportNewFrames,

  // number of times unwind_stop is called without a trace
  metricID_ErrEmptyStack,

  // number of attempted Hotspot unwinds
  metricID_UnwindHotspotAttempts,

  // number of unwound Hotspot frames
  metricID_UnwindHotspotFrames,

  // number of failures to get codeblob address (no heap or bad segmap)
  metricID_UnwindHotspotErrNoCodeblob,

  // number of failures to get codeblob data or match it to current unwind state
  metricID_UnwindHotspotErrInvalidCodeblob,

  // number of failures to unwind interpreter due to invalid FP
  metricID_UnwindHotspotErrInterpreterFP,

  // number of failures to unwind because PC is outside matched codeblob code range
  metricID_UnwindHotspotErrPCOutsideCodeblobCode,

  // number of failures to unwind because return address was not found with heuristic
  metricID_UnwindHotspotErrInvalidRA,

  // number of times we encountered frame sizes larger than the supported maximum
  metricID_UnwindHotspotUnsupportedFrameSize,

  // number of times that PC hold a value smaller than 0x1000
  metricID_UnwindNativeSmallPC,

  // number of times that a lookup of a inner map for stack deltas failed
  metricID_UnwindNativeErrLookupStackDeltaInnerMap,

  // number of times that a lookup of the outer map for stack deltas failed
  metricID_UnwindNativeErrLookupStackDeltaOuterMap,

  // number of times the bpf helper failed to get the current comm of the task
  metricID_ErrBPFCurrentComm,

  // number of attempted Ruby unwinds
  metricID_UnwindRubyAttempts,

  // number of unwound Ruby frames
  metricID_UnwindRubyFrames,

  // number of attempted V8 unwinds
  metricID_UnwindV8Attempts,

  // number of unwound V8 frames
  metricID_UnwindV8Frames,

  // number of failures to read V8 frame pointer data
  metricID_UnwindV8ErrBadFP,

  // number of failures to read V8 JSFunction object
  metricID_UnwindV8ErrBadJSFunc,

  // number of failures to read V8 Code object
  metricID_UnwindV8ErrBadCode,

  // number of cache hits of known traces
  metricID_KnownTracesHit,

  // number of cache misses of known traces
  metricID_KnownTracesMiss,

  // number of times we failed to update reported_pids
  metricID_ReportedPIDsErr,

  // number of times frame unwinding failed because of LR == 0
  metricID_UnwindNativeLr0,

  // number of PID_EVENT_TYPE_NEW events sent to userspace
  metricID_NumProcNew,

  // number of PID_EVENT_TYPE_EXIT events sent to userspace
  metricID_NumProcExit,

  // number of PID_EVENT_TYPE_UNKNOWN_PC sent to userspace
  metricID_NumUnknownPC,

  // number of PID_EVENT_TYPE_TRACES_FOR_SYMBOLIZATION sent to userspace
  metricID_NumSymbolizeTrace,

  // number of munmap events sent to userspace
  metricID_NumMunmapEvent,

  //
  // Metric IDs above are for counters (cumulative values)
  //
  metricID_BeginCumulative,
  //
  // Metric IDs below are for gauges (instantaneous values)
  //

  // current size of the hash map mmap_monitor
  metricID_HashmapMmapMonitor,

  // current size of the hash map mmap_executable
  metricID_HashmapMmapExecutable,

  // current size of the hash map mprotect_executable
  metricID_HashmapMprotectExecutable,

  // used as size for maps/metrics (BPF_MAP_TYPE_PERCPU_ARRAY)
  metricID_Max
};

// TracePrograms provide the offset for each eBPF trace program in the
// map that holds them.
// The values of this enum must fit in a single byte.
typedef enum TracePrograms {
  PROG_UNWIND_STOP,
  PROG_UNWIND_NATIVE,
  PROG_UNWIND_HOTSPOT,
  PROG_UNWIND_PERL,
  PROG_UNWIND_PYTHON,
  PROG_UNWIND_PHP,
  PROG_WALK_PYTHON_STACK,
  PROG_REPORT_TRACE,
  PROG_UNWIND_RUBY,
  PROG_UNWIND_V8,
  NUM_TRACER_PROGS,
} TracePrograms;

// The maximum number of characters we support in a function name.
#define MAX_FILE_NAME_LEN 256
// The maximum number of items in an Trace object's stack.
#define MAX_STACK_LEN 16

// Type to represent the hash value of a stack trace.
typedef u64 TraceHash;

// MAX_FRAME_UNWINDS defines the maximum number of frames per
// Trace we can unwind and respect the limit of eBPF instructions,
// limit of tail calls and limit of stack size per eBPF program.
//
// In report_frames and hash_trace we manually unrolled
// the looping over the frame stacks in per_cpu_frame_list.
// If you change this number, also update these two functions.
#define MAX_FRAME_UNWINDS 96

// MAX_FRAME_LIST_SIZE defines the number of frames we
// temporary store in each frame list in the eBPF map
// per_cpu_frame_lists.
// To satisfy verifier requirements, this number has to
// be in form of 2^n.
#define MAX_FRAME_LIST_SIZE 16

// MAX_FRAME_LISTS defines the maximum number of frame lists
// we temporary store in per_cpu_frame_stack.
#define MAX_FRAME_LISTS (MAX_FRAME_UNWINDS / MAX_FRAME_LIST_SIZE)


// FRAME_LIST_PRIME_XX define prime numbers that are used to multiple
// a hash of a frame list to make the hash of the trace unique.
// For each frame list we need to have a unique prime number.
//
// Changing these primes will result in break of backwards compatibility
// being able  to compare traces with the same frames.
#define FRAME_LIST_PRIME_0  5
#define FRAME_LIST_PRIME_1  17
#define FRAME_LIST_PRIME_2  37
#define FRAME_LIST_PRIME_3  61
#define FRAME_LIST_PRIME_4  89
#define FRAME_LIST_PRIME_5  127

// FRAME_CONTENT_PRIME defines MAX_FRAME_LIST_SIZE large prime numbers,
// that are used to hash the files and linenos of a FrameList.
static const u64 FRAME_CONTENT_PRIME[MAX_FRAME_LIST_SIZE] = {
  16576144079302944559ULL,
  2186004484194203119ULL,
  11172729313195809529ULL,
  12813429998291790233ULL,
  18270836424055081333ULL,
  1902216791325332717ULL,
  6613110929925725887ULL,
  7424432044193291893ULL,
  5003464939776917567ULL,
  12445729212826957111ULL,
  15427968335075868449ULL,
  11531585458220364679ULL,
  10179302947144594243ULL,
  15269173932701057419ULL,
  15644478762211198373ULL,
  17710734944920619687ULL};

// FrameListID is used as unique identifier for a particular FrameList of
// a trace and its hash.
// As we split the userspace frame stack in the eBPF map hash_to_framelist
// into multiple FrameLists list_index indicates the number of this list for
// the hash in this map.
typedef struct FrameListID {
  TraceHash hash;
  u8 list_index;
} FrameListID;

// FrameList stores up to MAX_FRAME_LIST_SIZE frames for a particular
// trace in its struct.
// This struct is then used to report the unwinded frames to userspace
// via the eBPF map hash_to_framelist.
typedef struct FrameList {
  // An array of IDs that uniquely identify a file combination
  u64 files[MAX_FRAME_LIST_SIZE];
  // For PHP this is an array of line numbers, corresponding to
  // the files in `stack`. For Python, each value provides information
  // to allow for the recovery of the line number associated with its
  // corresponding offset in `stack`. The lower 32 bits provide the
  // co_firstlineno value and the upper 32 bits provide the f_lasti value.
  u64 linenos[MAX_FRAME_LIST_SIZE];
  // frame_types indicates the type of the frame (Python, PHP, native etc)
  // for each frame.
  u8 frame_types[MAX_FRAME_LIST_SIZE];
} FrameList;

// Type to represent a globally-unique file id to be used as key for a BPF hash map
typedef u64 FileID;

// PerlProcInfo is a container for the data needed to build a stack trace for a Perl process.
typedef struct PerlProcInfo {
  u64 stateAddr;
  u32 version;
  // Introspection data
  u16 interpreter_curcop, interpreter_curstackinfo;
  u8 stateInTLS, si_cxstack, si_next, si_cxix, si_type;
  u8 context_type, context_blk_oldcop, context_blk_sub_retop, context_blk_sub_cv, context_sizeof;
  u8 sv_flags, sv_any, svu_gp, xcv_flags, xcv_gv, gp_egv;
} PerlProcInfo;

// PyProcInfo is a container for the data needed to build a stack trace for a Python process.
typedef struct PyProcInfo {
  // The address of the autoTLSkey variable
  u64 autoTLSKeyAddr;
  // The address of the tstate_current variable
  u64 tstateCurrentAddr;
  u16 version;
  // The Python object member offsets
  u8 PyThreadState_frame;
  u8 PyFrameObject_f_back, PyFrameObject_f_code, PyFrameObject_f_lasti;
  u8 PyCodeObject_co_argcount, PyCodeObject_co_kwonlyargcount;
  u8 PyCodeObject_co_flags, PyCodeObject_co_firstlineno;
} PyProcInfo;

// PHPProcInfo is a container for the data needed to build a stack trace for a PHP process.
typedef struct PHPProcInfo {
  u64 current_execute_data;
  // Return address for JIT code (in Hybrid mode)
  u64 jit_return_address;
  // Offsets for structures we need to access in ebpf
  u8 zend_execute_data_function, zend_execute_data_opline, zend_execute_data_prev_execute_data;
  u8 zend_execute_data_this_type_info, zend_function_type, zend_op_lineno;
} PHPProcInfo;

// PHPJITProcInfo is a container for the data needed to detect if a PC corresponds to a PHP
// JIT program. This is used to adjust the return address.
typedef struct PHPJITProcInfo {
  u64 start, end;
} PHPJITProcInfo;

// HotspotProcInfo is a container for the data needed to build a stack trace
// for a Java Hotspot VM process.
typedef struct HotspotProcInfo {
  // The global JIT heap mapping. All JIT code is between these two address.
  u64 codecache_start, codecache_end;

  // Offsets of large structures, sizeof it is near or over 256 bytes.
  u16 compiledmethod_deopt_handler, nmethod_compileid, nmethod_orig_pc_offset;

  // Offsets and other data fitting in a uchar
  u8 codeblob_name;
  u8 codeblob_codestart, codeblob_codeend;
  u8 codeblob_framecomplete, codeblob_framesize;
  u8 heapblock_size, method_constmethod, cmethod_size;
  u8 jvm_version, segment_shift;
} HotspotProcInfo;

// RubyProcInfo is a container for the data needed to build a stack trace for a Ruby process.
typedef struct RubyProcInfo {
  // version of the Ruby interpreter.
  u32 version;

  // current_ctx_ptr holds the address of the symbol ruby_current_execution_context_ptr.
  u64 current_ctx_ptr;

  // Offsets and sizes of Ruby internal structs

  // rb_execution_context_struct offsets:
  u8 vm_stack, vm_stack_size, cfp;

  // rb_control_frame_struct offsets:
  u8 pc, iseq, ep, size_of_control_frame_struct;

  // rb_iseq_struct offsets:
  u8 body;

  // rb_iseq_constant_body:
  u8 iseq_type, iseq_encoded, iseq_size;

  // size_of_value holds the size of the macro VALUE as defined in
  // https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L1136
  u8 size_of_value;

  // rb_ractor_struct offset:
  u16 running_ec;

} RubyProcInfo;

// V8ProcInfo is a container for the data needed to build a stack trace for a V8 process.
typedef struct V8ProcInfo {
  u32 version;
  // Introspection data
  u16 type_JSFunction, type_Code, type_BytecodeArray;
  u8 off_HeapObject_map, off_Map_instancetype, off_JSFunction_code;
  u8 off_Code_instruction_start, off_Code_instruction_size;
  s8 off_fp_marker, off_fp_function, off_fp_bytecode_array, off_fp_bytecode_offset;
} V8ProcInfo;

// COMM_LEN defines the maximum length we will receive for the comm of a task.
#define COMM_LEN 16

// Container for a stack trace
typedef struct Trace {
  // The process ID
  u32 pid;

  // The current comm of the thread of this Trace
  char comm[COMM_LEN];

  // The hash over the frames of this Trace is calculated just
  // before reporting this Trace to user space.
  TraceHash hash;

  // The kernel stack ID
  s32 kernel_stack_id;
  // The number of items in the stack
  u32 stack_len;

  // Python-specific data
  bool python_gil_held;
} Trace;

// Container for unwinding state
typedef struct UnwindState {
  // Current register value for Program Counter
  u64 pc;
  // Current register value for Stack Pointer
  u64 sp;
  // Current register value for Frame Pointer
  u64 fp;

  union {
    // Current register value for r13
    u64 r13;  //x86-64

    // Current register value for lr
    u64 lr;   //ARM64
  };

  // The executable ID/hash associated with PC
  u64 text_section_id;
  // PC converted into the offset relative to the executables text section
  u64 text_section_offset;
  // The current mapping load bias
  u64 text_section_bias;

  // Unwind error condition to process and report in unwind_stop()
  s32 error_metric;
} UnwindState;

// Container for unwinding state needed by the Perl unwinder. Keeping track of
// current stackinfo, first seen COP, and the info about current context stack.
typedef struct PerlUnwindState {
  // Pointer to the next stackinfo to unwind
  const void *stackinfo;
  // First Control OP seen for the frame filename/linenumber info for next function frame
  const void *cop;
  // Current context state, pointer to the base and current entries
  const void *cxbase, *cxcur;
} PerlUnwindState;

// Container for unwinding state needed by the Python unwinder. At the moment
// the only thing we need to pass between invocations of the unwinding programs
// is the pointer to the next PyFrameObject to unwind.
typedef struct PythonUnwindState {
  // Pointer to the next PyFrameObject to unwind
  void *py_frame;
} PythonUnwindState;

// Container for unwinding state needed by the PHP unwinder. At the moment
// the only thing we need to pass between invocations of the unwinding programs
// is the pointer to the next zend_execute_data to unwind.
typedef struct PHPUnwindState {
  // Pointer to the next zend_execute_data to unwind
  const void *zend_execute_data;
} PHPUnwindState;

// Container for unwinding state needed by the Ruby unwinder.
typedef struct RubyUnwindState {
  // Pointer to the next control frame struct in the Ruby VM stack we want to unwind.
  void *stack_ptr;
  // Pointer to the last control frame struct in the Ruby VM stack we want to handle.
  void *last_stack_frame;
} RubyUnwindState;

// Container for additional scratch space needed by the HotSpot unwinder.
typedef struct HotspotUnwindScratchSpace {
  // Read buffer for storing the codeblob. It's not needed across calls, but the buffer is too
  // large to be allocated on stack. With my debug build of JDK17, the largest possible variant of
  // codeblob that we care about (nmethod) is 376 bytes in size. 512 bytes should thus be plenty.
  u8 codeblob[512];
} HotspotUnwindScratchSpace;

// Per-CPU info for the stack being built. This contains the stack as well as
// meta-data on the number of eBPF tail-calls used so far to construct it.
typedef struct PerCPURecord {
  // The output record, including the stack being built.
  Trace trace;
  // The current unwind state.
  UnwindState state;
  // The current Perl unwinder state
  PerlUnwindState perlUnwindState;
  // The current Python unwinder state.
  PythonUnwindState pythonUnwindState;
  // The current PHP unwinder state.
  PHPUnwindState phpUnwindState;
  // The current Ruby unwinder state.
  RubyUnwindState rubyUnwindState;
  // Scratch space for the HotSpot unwinder.
  HotspotUnwindScratchSpace hotspotUnwindScratch;

  // If current Trace has frames that require HA client side symbolization.
  bool ha_symbolization_needed;
  // Next unwinder for interpreter loop to call.
  u8 next_unwinder;
} PerCPURecord;

// UnwindInfo contains the unwind information needed to unwind one frame
// from a specific address.
typedef struct UnwindInfo {
  u8 opcode;       // main opcode to unwind CFA
  u8 fpOpcode;     // opcode to unwind FP
  u8 mergeOpcode;  // opcode for generating next stack delta, see below
  s32 param;       // parameter for the CFA expression
  s32 fpParam;     // parameter for the FP expression
} UnwindInfo;

// The 8-bit mergeOpcode consists of two separate fields:
//  1 bit   the adjustment to 'param' is negative (-8), if not set positive (+8)
//  7 bits  the difference to next 'addrLow'
#define MERGEOPCODE_NEGATIVE 0x80

// An array entry that we will bsearch into that keeps address and stack unwind
// info, per executable.
typedef struct StackDelta {
  u16 addrLow;    // the low 16-bits of the ELF virtual address to which this stack delta applies
  u16 unwindInfo; // index of UnwindInfo, or UNWIND_COMMAND_* if STACK_DELTA_COMMAND_FLAG is set
} StackDelta;

// unwindInfo flag indicating that the value is UNWIND_COMMAND_* value and not an index to
// the unwind info array. When UnwindInfo.opcode is UNWIND_OPCODE_COMMAND the 'param' gives
// the UNWIND_COMMAND_* which describes the exact handling for this stack delta (all
// CFA/PC/FP recovery, or stop condition), and the eBPF code needs special code to handle it.
// This basically serves as a minor optimization to not take a slot from unwind info array,
// nor require a table lookup for these special cased stack deltas.
#define STACK_DELTA_COMMAND_FLAG 0x8000

// StackDeltaPageKey is the look up key for stack delta page map.
typedef struct StackDeltaPageKey {
  u64 fileID;
  u64 page;
} StackDeltaPageKey;

// StackDeltaPageInfo contains information of stack delta page so the correct map
// and range of StackDelta entries can be found.
typedef struct StackDeltaPageInfo {
  u32 firstDelta;
  u16 numDeltas;
  u16 mapID;
} StackDeltaPageInfo;


// Keep stack deltas in 64kB pages to limit search space and to fit the low address
// bits into the addrLow field of struct StackDelta.
#define STACK_DELTA_PAGE_BITS 16

// The binary mask for STACK_DELTA_PAGE_BITS, which can be used to and/nand an address
// for its page number and offset within that page.
#define STACK_DELTA_PAGE_MASK ((1 << STACK_DELTA_PAGE_BITS) - 1)

// In order to determine whether a given PC falls into the main interpreter loop
// of an interpreter, we need to store some data: The lower boundary of the loop,
// the upper boundary of the loop, and the relevant index to call in the prog
// array.
typedef struct OffsetRange {
  u64 lower_offset;
  u64 upper_offset;
  u16 program_index;  // The interpreter-specific program index to call.
} OffsetRange;

// Number of bytes of code to extract to userspace via codedump helper.
// Needed for tpbase offset calculations.
#define CODEDUMP_BYTES 64

// MunmapEvent holds the information that is sent through the report_munmap_events perf event output
// channel.
typedef struct MunmapEvent {
  u32 pid;  // process ID of which the event is about.
  u64 addr; // address of the memory unmapping.
} MunmapEvent;

// PIDEvent is the header for all PID related events sent through the report_pid_events
// perf event output channel
typedef struct PIDEvent {
  u32 pid;        // process ID of which the event is about
  u32 event_type; // PID_EVENT_TYPE_xxx selector of event
} PIDEvent;

#define PID_EVENT_TYPE_NEW                      1
#define PID_EVENT_TYPE_EXIT                     2
#define PID_EVENT_TYPE_TRACES_FOR_SYMBOLIZATION 3
#define PID_EVENT_TYPE_UNKNOWN_PC               4

// UnknownPC is the key structure of the eBPF map defer_pc and holds PID/PC combinations
// for which we do not know the related executable memory mapping.
typedef struct UnknownPC {
  u32 pid;
  u64 pc;
} UnknownPC;

// PIDPage represents the key of the eBPF map pid_page_to_mapping_info.
typedef struct PIDPage {
  u32 prefixLen;    // Number of bits for pid and page that defines the
                    // longest prefix.

  __be32 pid;       // Unique ID of the process.
  __be64 page;      // Address to a certain part of memory within PID.
} PIDPage;


// BIT_WIDTH_PID defines the number of bits used in the value pid of the PIDPage struct.
#define BIT_WIDTH_PID  32
// BIT_WIDTH_PAGE defines the number of bits used in the value page of the PIDPage struct.
#define BIT_WIDTH_PAGE 64

// PIDPageMappingInfo represents the value of the eBPF map pid_page_to_mapping_info.
typedef struct PIDPageMappingInfo {
  u64 file_id;                  // Unique identifier for the executable file

    // Load bias (7 bytes) + unwinding program to use (1 byte, shifted 7 bytes to the left), encoded in a u64.
    // We can do so because the load bias is for userspace addresses, for which the most significant byte is always 0 on
    // relevant architectures.
    // This encoding may have to be changed if bias can be negative.
  u64 bias_and_unwind_program;
} PIDPageMappingInfo;

// UNKNOWN_FILE indicates for unknown files.
#define UNKNOWN_FILE 0x0
// FUNC_TYPE_UNKNOWN indicates an unknown interpreted function.
#define FUNC_TYPE_UNKNOWN 0xfffffffffffffffe
// FUNC_TYPE_INTERNAL indicates an internal interpreted function.
#define FUNC_TYPE_INTERNAL 0xfffffffffffffffd

// Max entries of map pycodeobject_to_fileid, also used in pf-host-agent/ebpf.ebpf.go
#define MAX_PYCODEOBJECT_ENTRIES 4*1024

// Builds a bias_and_unwind_program value for PIDPageMappingInfo
static inline __attribute__((__always_inline__))
u64 encode_bias_and_unwind_program(u64 bias, int unwind_program) {
    return bias | (((u64)unwind_program) << 56);
}

// Reads a bias_and_unwind_program value from PIDPageMappingInfo
static inline __attribute__((__always_inline__))
void decode_bias_and_unwind_program(u64 bias_and_unwind_program, u64* bias, int* unwind_program) {
    *bias = bias_and_unwind_program & 0x00FFFFFFFFFFFFFF;
    *unwind_program = bias_and_unwind_program >> 56;
}

// Smallest stack delta bucket that holds up to 2^8 entries
#define STACK_DELTA_BUCKET_SMALLEST 8
// Largest stack delta bucket that holds up to 2^21 entries
#define STACK_DELTA_BUCKET_LARGEST 21

// Struct of the `system_config` map. Contains various configuration variables
// determined and set by the host agent.
typedef struct SystemConfig {
  // PAC mask that is determined by user-space and used in `normalize_pac_ptr`.
  // ARM64 specific, `MAX_U64` otherwise.
  u64 inverse_pac_mask;

  // The offset of the Thread Pointer Base variable in `task_struct`. It is
  // populated by the host agent based on kernel code analysis.
  u64 tpbase_offset;
} SystemConfig;

#endif
