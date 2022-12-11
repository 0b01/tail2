#undef asm_volatile_goto
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

#include "bpfdefs.h"

#ifdef TESTING
  #include <sys/types.h>
  #include <unistd.h>

// defined in include/uapi/linux/perf_event.h
#define PERF_MAX_STACK_DEPTH 127

#ifndef THREAD_SIZE
  // taken from the kernel sources
  #define THREAD_SIZE 16384
#endif

#else
  #include <linux/sched.h>
  #include <uapi/linux/bpf_perf_event.h>
  #include <uapi/linux/ptrace.h>
  #include <uapi/linux/perf_event.h>
#endif

#include "frametypes.h"
#include "types.h"
#include "tracemgmt.h"
#include "stackdeltatypes.h"

// Macro to create a map named exe_id_to_X_stack_deltas that is a nested maps with a fileID for the
// outer map and an array as inner map that holds up to 2^X stack delta entries for the given fileID.
#define STACK_DELTA_BUCKET(X)                                                            \
  bpf_map_def SEC("maps/exe_id_to_" #X "_stack_deltas") exe_id_to_##X##_stack_deltas = { \
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,                                                   \
    .key_size = sizeof(u64),                                                             \
    .value_size = sizeof(u32),                                                           \
    .max_entries = 4096,                                                                 \
  };

// Create buckets to hold the stack delta information for the executables.
STACK_DELTA_BUCKET(8);
STACK_DELTA_BUCKET(9);
STACK_DELTA_BUCKET(10);
STACK_DELTA_BUCKET(11);
STACK_DELTA_BUCKET(12);
STACK_DELTA_BUCKET(13);
STACK_DELTA_BUCKET(14);
STACK_DELTA_BUCKET(15);
STACK_DELTA_BUCKET(16);
STACK_DELTA_BUCKET(17);
STACK_DELTA_BUCKET(18);
STACK_DELTA_BUCKET(19);
STACK_DELTA_BUCKET(20);
STACK_DELTA_BUCKET(21);

// Unwind info value for invalid stack delta
#define STACK_DELTA_INVALID (STACK_DELTA_COMMAND_FLAG | UNWIND_COMMAND_INVALID)
#define STACK_DELTA_STOP    (STACK_DELTA_COMMAND_FLAG | UNWIND_COMMAND_STOP)

// An array of unwind info contains the all the different UnwindInfo instances
// needed system wide. Individual stack delta entries refer to this array.
bpf_map_def SEC("maps/unwind_info_array") unwind_info_array = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(UnwindInfo),
  // Maximum number of unique stack deltas needed on a system. This is based on
  // normal desktop /usr/bin/* and /usr/lib/*.so having about 9700 unique deltas.
  // Can be increased up to 2^15, see also STACK_DELTA_COMMAND_FLAG.
  .max_entries = 16384,
};

// The number of native frames to unwind per frame-unwinding eBPF program.
#define NATIVE_FRAMES_PER_PROGRAM 4

// The decision whether to unwind native stacks or interpreter stacks is made by checking if a given
// PC address falls into the "interpreter loop" of an interpreter. This map helps identify such
// loops: The keys are those executable section IDs that contain interpreter loops, the values
// identify the offset range within this executable section that contains the interpreter loop.
bpf_map_def SEC("maps/interpreter_offsets") interpreter_offsets = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(u64),
  .value_size = sizeof(OffsetRange),
  .max_entries = 32,
};

// Maps fileID and page to information of stack deltas associated with that page.
bpf_map_def SEC("maps/stack_delta_page_to_info") stack_delta_page_to_info = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(StackDeltaPageKey),
  .value_size = sizeof(StackDeltaPageInfo),
  .max_entries = 40000,
};

// This contains the kernel PCs as returned by bpf_get_stackid(). Unfortunately the ebpf
// program cannot read the contents, so we return the stackid in the Trace directly, and
// make pf-host-agent read the kernel mode stack trace portion from this map.
bpf_map_def SEC("maps/kernel_stackmap") kernel_stackmap = {
  .type = BPF_MAP_TYPE_STACK_TRACE,
  .key_size = sizeof(u32),
  .value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
  .max_entries = 16*1024,
};

#if defined(__aarch64__)
// This contains the cached value of the pt_regs size structure as established by the
// get_arm64_ptregs_size function
struct bpf_map_def SEC("maps/ptregs_size") ptregs_size = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(u64),
  .max_entries = 1,
};
#endif

// Record a native frame
static inline __attribute__((__always_inline__))
int push_native(Trace *trace, u64 file, u64 line) {
  return _push(trace, file, line, FRAME_MARKER_NATIVE);
}

#ifdef __aarch64__
// Strips the PAC tag from a pointer.
//
// While all pointers can contain PAC tags, we only apply this function to code pointers, because
// that's where normalization is required to make the stack delta lookups work. Note that if that
// should ever change, we'd need a different mask for the data pointers, because it might diverge
// from the mask for code pointers.
static inline u64 normalize_pac_ptr(u64 ptr) {
  // Retrieve PAC mask from the system config.
  u32 key = 0;
  SystemConfig* syscfg = bpf_map_lookup_elem(&system_config, &key);
  if (!syscfg) {
    // Unreachable: array maps are always fully initialized.
    return ptr;
  }

  // Mask off PAC bits. Since we're always applying this to usermode pointers that should have all
  // the high bits set to 0, we don't need to consider the case of having to fill up the resulting
  // hole with 1s (like we'd have to for kernel ptrs).
  ptr &= syscfg->inverse_pac_mask;
  return ptr;
}
#endif

// A single step for the bsearch into the big_stack_deltas array. This is really a textbook bsearch
// step, built in a way to update the value of *lo and *hi. This function will be called repeatedly
// (since we cannot do loops). The return value signals whether the bsearch came to an end / found
// the right element or whether it needs to continue.
static inline __attribute__((__always_inline__))
bool bsearch_step(void* inner_map, u32* lo, u32* hi, u16 page_offset) {
  u32 pivot = (*lo + *hi) >> 1;
  StackDelta *delta = bpf_map_lookup_elem(inner_map, &pivot);
  if (!delta) {
    *hi = 0;
    return false;
  }
  if (page_offset >= delta->addrLow) {
    *lo = pivot + 1;
  } else {
    *hi = pivot;
  }
  return *lo < *hi;
}

// Get the outer map based on the number of stack delta entries.
static inline __attribute__((__always_inline__))
void *get_stack_delta_map(int mapID) {
  switch (mapID) {
  case  8: return &exe_id_to_8_stack_deltas;
  case  9: return &exe_id_to_9_stack_deltas;
  case 10: return &exe_id_to_10_stack_deltas;
  case 11: return &exe_id_to_11_stack_deltas;
  case 12: return &exe_id_to_12_stack_deltas;
  case 13: return &exe_id_to_13_stack_deltas;
  case 14: return &exe_id_to_14_stack_deltas;
  case 15: return &exe_id_to_15_stack_deltas;
  case 16: return &exe_id_to_16_stack_deltas;
  case 17: return &exe_id_to_17_stack_deltas;
  case 18: return &exe_id_to_18_stack_deltas;
  case 19: return &exe_id_to_19_stack_deltas;
  case 20: return &exe_id_to_20_stack_deltas;
  case 21: return &exe_id_to_21_stack_deltas;
  default: return NULL;
  }
}

// Get the stack offset of the given instruction.
static u32 get_stack_delta(u64 text_section_id, u64 text_section_offset, int *addrDiff) {
  u64 exe_id = text_section_id;

  // Look up the stack delta page information for this address.
  StackDeltaPageKey key = { };
  key.fileID = text_section_id;
  key.page = text_section_offset & ~STACK_DELTA_PAGE_MASK;
  DEBUG_PRINT("Look up stack delta for %lx:%lx",
    (unsigned long)text_section_id, (unsigned long)text_section_offset);
  StackDeltaPageInfo *info = bpf_map_lookup_elem(&stack_delta_page_to_info, &key);
  if (!info) {
    DEBUG_PRINT("Failure to look up stack delta page fileID %lx, page %lx",
                (unsigned long)key.fileID, (unsigned long)key.page);
    increment_metric(metricID_UnwindNativeErrLookupTextSection);
    return STACK_DELTA_INVALID;
  }

  void *outer_map = get_stack_delta_map(info->mapID);
  if (!outer_map) {
    DEBUG_PRINT("Failure to look up outer map for text section %lx in mapID %d",
                (unsigned long) exe_id, (int) info->mapID);
    increment_metric(metricID_UnwindNativeErrLookupStackDeltaOuterMap);
    return STACK_DELTA_INVALID;
  }

  void *inner_map = bpf_map_lookup_elem(outer_map, &exe_id);
  if (!inner_map) {
    DEBUG_PRINT("Failure to look up inner map for text section %lx",
                (unsigned long) exe_id);
    increment_metric(metricID_UnwindNativeErrLookupStackDeltaInnerMap);
    return STACK_DELTA_INVALID;
  }

  // Preinitialize the idx for the index to use for page without any deltas.
  u32 idx = info->firstDelta;
  u16 page_offset = text_section_offset & STACK_DELTA_PAGE_MASK;
  if (info->numDeltas) {
    // Page has deltas, so find the correct one to use using binary search.
    u32 lo = info->firstDelta;
    u32 hi = lo + info->numDeltas;

    DEBUG_PRINT("Intervals should be from %lu to %lu (mapID %d)",
      (unsigned long) lo, (unsigned long) hi, (int)info->mapID);

    // Do the binary search, up to 16 iterations. Deltas are paged to 64kB pages.
    // They can contain at most 64kB deltas even if everything is single byte opcodes.
    int i;
#pragma unroll
    for (i = 0; i < 16; i++) {
      if (!bsearch_step(inner_map, &lo, &hi, page_offset)) {
        break;
      }
    }
    if (i >= 16 || hi == 0) {
      DEBUG_PRINT("Failed bsearch in 16 steps. Corrupt data?");
      increment_metric(metricID_UnwindNativeErrLookupIterations);
      return STACK_DELTA_INVALID;
    }
    // After bsearch, 'hi' points to the first entry greater than the requested.
    idx = hi;
  }

  // The code above found the first entry with greater address than requested,
  // so it needs to be decremented by one to get the entry with equal-or-less.
  // This makes also the logic work cross-pages: if the first entry in within
  // the page is too large, this actually gets the entry from the previous page.
  idx--;

  StackDelta *delta = bpf_map_lookup_elem(inner_map, &idx);
  if (!delta) {
    increment_metric(metricID_UnwindNativeErrLookupRange);
    return STACK_DELTA_INVALID;
  }

  DEBUG_PRINT("delta index %d, addrLow 0x%x, unwindInfo %d",
    idx, delta->addrLow, delta->unwindInfo);

  // Calculate PC delta from stack delta for merged delta comparison
  int deltaOffset = (int)page_offset - (int)delta->addrLow;
  if (idx < info->firstDelta) {
    // PC is below the first delta of the corresponding page. This means that
    // delta->addrLow contains address relative to one page before the page_offset.
    // Fix up the deltaOffset with this difference of base pages.
    deltaOffset += 1 << STACK_DELTA_PAGE_BITS;
  }
  *addrDiff = deltaOffset;

  if (delta->unwindInfo == STACK_DELTA_INVALID) {
    increment_metric(metricID_UnwindNativeErrStackDeltaInvalid);
  }
  if (delta->unwindInfo == STACK_DELTA_STOP) {
    increment_metric(metricID_UnwindNativeStackDeltaStop);
  }
  return delta->unwindInfo;
}

// unwind_register_address calculates the given expression ('opcode'/'param') to get
// the CFA (canonical frame addres, to recover PC and be used in further calculations),
// or the address where a register is stored (FP currently), so that the value of
// the register can be recovered.
//
// Currently the following expressions are supported:
//   1. Not recoverable -> NULL is returned.
//   2. When UNWIND_OPCODEF_DEREF is not set:
//      BASE + param
//   3. When UNWIND_OPCODEF_DEREF is set:
//      *(BASE + preDeref) + postDeref
static inline __attribute__((__always_inline__))
u64 unwind_register_address(UnwindState *state, u64 cfa, u8 opcode, s32 param) {
  unsigned long addr, val;
  s32 preDeref = param, postDeref = 0;

  if (opcode & UNWIND_OPCODEF_DEREF) {
    // For expressions that dereference the base expression, the parameter is constructed
    // of pre-dereference and post-derefence operands. Unpack those.
    preDeref &= ~UNWIND_DEREF_MASK;
    postDeref = (param & UNWIND_DEREF_MASK) * UNWIND_DEREF_MULTIPLIER;
  }

  // Resolve the 'BASE' register, and fetch the CFA/FP/SP value.
  switch (opcode & ~UNWIND_OPCODEF_DEREF) {
  case UNWIND_OPCODE_BASE_CFA:
    addr = cfa;
    break;
  case UNWIND_OPCODE_BASE_FP:
    addr = state->fp;
    break;
  case UNWIND_OPCODE_BASE_SP:
    addr = state->sp;
    break;
#if defined(__aarch64__)
  case UNWIND_OPCODE_BASE_LR:
    DEBUG_PRINT("unwind: lr");

    if (state->lr == 0) {
        increment_metric(metricID_UnwindNativeLr0);
        DEBUG_PRINT("Failure to unwind frame: zero LR at %llx", state->pc);
        return 0;
    }

    return state->lr;
#endif
  default:
    return 0;
  }

#ifdef OPTI_DEBUG
  switch (opcode) {
  case UNWIND_OPCODE_BASE_CFA:
    DEBUG_PRINT("unwind: cfa+%d", preDeref);
    break;
  case UNWIND_OPCODE_BASE_FP:
    DEBUG_PRINT("unwind: fp+%d", preDeref);
    break;
  case UNWIND_OPCODE_BASE_SP:
    DEBUG_PRINT("unwind: sp+%d", preDeref);
    break;
  case UNWIND_OPCODE_BASE_CFA | UNWIND_OPCODEF_DEREF:
    DEBUG_PRINT("unwind: *(cfa+%d)+%d", preDeref, postDeref);
    break;
  case UNWIND_OPCODE_BASE_FP | UNWIND_OPCODEF_DEREF:
    DEBUG_PRINT("unwind: *(fp+%d)+%d", preDeref, postDeref);
    break;
  case UNWIND_OPCODE_BASE_SP | UNWIND_OPCODEF_DEREF:
    DEBUG_PRINT("unwind: *(sp+%d)+%d", preDeref, postDeref);
    break;
  }
#endif

  // Adjust based on parameter / preDereference adder.
  addr += preDeref;
  if ((opcode & UNWIND_OPCODEF_DEREF) == 0) {
    // All done: return "BASE + param"
    return addr;
  }

  // Dereference, and add the postDereference adder.
  if (bpf_probe_read(&val, sizeof(val), (void*) addr)) {
    DEBUG_PRINT("unwind failed to dereference address 0x%lx", addr);
    return 0;
  }
  // Return: "*(BASE + preDeref) + postDeref"
  return val + postDeref;
}

// Stack unwinding in the absence of frame pointers can be a bit involved, so
// this comment explains what the following code does.
//
// One begins unwinding a frame somewhere in the middle of execution.
// On x86_64, registers RIP (PC), RSP (SP), and RBP (FP) are available.
//
// This function resolves a "stack delta" command from from our internal maps.
// This stack delta refers to a rule on how to unwind the state. In the simple
// case it just provides SP delta and potentially offset from where to recover
// FP value. See unwind_register_address() on the expressions supported.
//
// Returning "false" means that the main ebpf unwinder should exit. This can
// be because of being in a trace start function (unwind info says no parent),
// or because something went wrong and the next function is not available.
// In both cases this function increments the proper error metric.
// Some applications might indicate the trace start function by storing a zero
// PC value in the return address. In this case this function returns true.
#if defined(__x86_64__)
static bool unwind_one_frame(u64 pid, u32 frame_idx, UnwindState *state) {
  int addrDiff = 0;
  u64 cfa = 0;
  // The relevant executable is compiled with frame pointer omission, so
  // stack deltas need to be retrieved from the relevant map.
  u32 delta = get_stack_delta(state->text_section_id, state->text_section_offset, &addrDiff);

  if (delta & STACK_DELTA_COMMAND_FLAG) {
    switch (delta & ~STACK_DELTA_COMMAND_FLAG) {
    case UNWIND_COMMAND_PLT:
      // The toolchains routinely emit a fixed DWARF expression to unwind the full
      // PLT table with one expression to reduce .eh_frame size.
      // This is the hard coded implementation of this expression. For further details,
      // see https://hal.inria.fr/hal-02297690/document, page 4. (DOI: 10.1145/3360572)
      cfa = state->sp + 8 + ((((state->pc & 15) >= 11) ? 1 : 0) << 3);
      DEBUG_PRINT("PLT, cfa=0x%lx", (unsigned long)cfa);
      break;
    case UNWIND_COMMAND_INVALID:
    case UNWIND_COMMAND_STOP:
    default:
      // Proper metric was incremented already in get_stack_delta().
      return false;
    }
  } else {
    UnwindInfo *info = bpf_map_lookup_elem(&unwind_info_array, &delta);
    if (!info) {
      increment_metric(metricID_UnwindNativeErrStackDeltaInvalid);
      return false;
    }

    s32 param = info->param;
    if (info->mergeOpcode) {
      DEBUG_PRINT("AddrDiff %d, merged delta %#02x", addrDiff, info->mergeOpcode);
      if (addrDiff >= (info->mergeOpcode & ~MERGEOPCODE_NEGATIVE)) {
        param += (info->mergeOpcode & MERGEOPCODE_NEGATIVE) ? -8 : 8;
        DEBUG_PRINT("Merged delta match: cfaDelta=%d", delta);
      }
    }

    // Resolve the frame's CFA (previous PC is fixed to CFA) address, and
    // the previous FP address if any.
    cfa = unwind_register_address(state, 0, info->opcode, param);
    u64 fpa = unwind_register_address(state, cfa, info->fpOpcode, info->fpParam);

    if (fpa) {
      bpf_probe_read(&state->fp, sizeof(state->fp), (void*)fpa);
    } else if (info->opcode == UNWIND_OPCODE_BASE_FP) {
      // FP used for recovery, but no new FP value received, clear FP
      state->fp = 0;
    }
  }

  if (!cfa || bpf_probe_read(&state->pc, sizeof(state->pc), (void*)(cfa - 8))) {
    increment_metric(metricID_UnwindNativeErrPCRead);
    return false;
  }
  state->sp = cfa;

  increment_metric(metricID_UnwindNativeFrames);
  return true;
}
#elif defined(__aarch64__)
static bool unwind_one_frame(u64 pid, u32 frame_idx, struct UnwindState *state) {
  int addrDiff = 0;
  u64 cfa = 0;
  // The relevant executable is compiled with frame pointer omission, so
  // stack deltas need to be retrieved from the relevant map.
  u32 delta = get_stack_delta(state->text_section_id, state->text_section_offset, &addrDiff);

  if (delta & STACK_DELTA_COMMAND_FLAG) {
    // Proper metric was incremented already in get_stack_delta().
    return false;
  }

  UnwindInfo *info = bpf_map_lookup_elem(&unwind_info_array, &delta);
  if (!info) {
    increment_metric(metricID_UnwindNativeErrStackDeltaInvalid);
    DEBUG_PRINT("Giving up due to invalid stack delta");
    return false;
  }

  s32 param = info->param;
  if (info->mergeOpcode) {
    DEBUG_PRINT("AddrDiff %d, merged delta %#02x", addrDiff, info->mergeOpcode);
    if (addrDiff >= (info->mergeOpcode & ~MERGEOPCODE_NEGATIVE)) {
      param += (info->mergeOpcode & MERGEOPCODE_NEGATIVE) ? -8 : 8;
      DEBUG_PRINT("Merged delta match: cfaDelta=%d", delta);
    }
  }

  // Resolve the frame CFA (previous PC is fixed to CFA) address
  cfa = unwind_register_address(state, 0, info->opcode, param);

  // Resolve Return Address, it is either the value of link register or
  // stack address where RA is stored
  u64 ra = unwind_register_address(state, cfa, info->fpOpcode, info->fpParam);
  if (ra) {
    if (info->fpOpcode == UNWIND_OPCODE_BASE_LR) {
      // Only first frame can ever have LR based unwinding. If we're asked to
      // unwind based on LR anywhere else, we most likely reached the entry
      // point that doesn't set up a proper stack frame.
      if (frame_idx != 0) {
        return false;
      }

      // set return address location to link register
      state->pc = ra;
    } else {
      DEBUG_PRINT("RA: %016llX", (u64)ra);

      // read the value of RA from stack
      if (bpf_probe_read(&state->pc, sizeof(state->pc), (void*)ra)) {
        // error reading memory, mark RA as invalid
        ra = 0;
      }
    }

    state->pc = normalize_pac_ptr(state->pc);
  }

  if (!ra) {
    // report failure to resolve RA and stop unwinding
    increment_metric(metricID_UnwindNativeErrPCRead);
    DEBUG_PRINT("Giving up due to failure to resolve RA");
    return false;
  }

  // Try to resolve frame pointer
  // simple heuristic for FP based frames
  // the GCC compiler usually generates stack frame records in such a way,
  // so that FP/RA pair is at the bottom of a stack frame (stack frame
  // record at lower addresses is followed by stack vars at higher ones)
  // this implies that if no other changes are applied to the stack such
  // as alloca(), following the prolog SP/FP points to the frame record
  // itself, in such a case FP offset will be equal to 8
  if (info->fpParam == 8) {
    // we can assume the presence of frame pointers
    if (info->fpOpcode != UNWIND_OPCODE_BASE_LR) {
      // FP precedes the RA on the stack (Aarch64 ABI requirement)
      bpf_probe_read(&state->fp, sizeof(state->fp), (void*)(ra - 8));
    }
  }

  state->sp = cfa;

  increment_metric(metricID_UnwindNativeFrames);
  return true;
}
#else
  #error unsupported architecture
#endif

// Initialize state from pt_regs
static inline void copy_state_regs(UnwindState *state, struct pt_regs *regs)
{
#if defined(__x86_64__)
  state->pc = regs->ip;
  state->sp = regs->sp;
  state->fp = regs->bp;
  state->r13 = regs->r13;
#elif defined(__aarch64__)
  state->pc = normalize_pac_ptr(regs->pc);
  state->sp = regs->sp;
  state->fp = regs->regs[29];
  state->lr = normalize_pac_ptr(regs->regs[30]);
#endif
}

#if defined(__aarch64__)
// on ARM64, the size of pt_regs structure is not constant across kernel
// versions as in x86-64 platform (!)
// get_arm64_ptregs_size tries to find out the size of this structure with the
// help of a simple heuristic, this size is needed for locating user process
// registers on kernel stack
static inline u64 get_arm64_ptregs_size(u64 stack_top) {
  // this var should be static, but verifier complains, in the meantime
  // just leave it here
  u32 key0 = 0;
  u64 pc, sp;

  u64 *paddr = bpf_map_lookup_elem(&ptregs_size, &key0);
  if (!paddr) {
    DEBUG_PRINT("Failed to look up ptregs_size map");
    return -1;
  }

  // read current (possibly cached) value of pt_regs structure size
  u64 arm64_ptregs_size = *paddr;

  // if the size of pt_regs has been already established, just return it
  if (arm64_ptregs_size) return arm64_ptregs_size;

  // assume default pt_regs structure size as for kernel 4.19.120
  arm64_ptregs_size = sizeof(struct pt_regs);

  // the candidate addr where pt_regs structure may start
  u64 ptregs_candidate_addr = stack_top - arm64_ptregs_size;

  struct pt_regs *regs = (struct pt_regs*)ptregs_candidate_addr;

  // read the value of pc and sp registers
  if (bpf_probe_read(&pc, sizeof(pc), &regs->pc) ||
      bpf_probe_read(&sp, sizeof(sp), &regs->sp)) {
      goto exit;
  }

  // if pc and sp are kernel pointers, we may assume correct candidate
  // addr of pt_regs structure (as seen 4.19.120 and 5.4.38 kernels)
  if (is_kernel_address(pc) && is_kernel_address(sp)) {
     DEBUG_PRINT("default pt_regs struct size");
     goto exit;
  }

  // this is likely pt_regs structure as present in kernel 5.10.0-7
  // with two extra fields in pt_regs:
  //    u64 lockdep_hardirqs;
  //    u64 exit_rcu;
  // Adjust arm64_ptregs_size for that
  DEBUG_PRINT("adjusted pt_regs struct size");
  arm64_ptregs_size += 2*sizeof(u64);

exit:
  // update the map (cache the value)
  if (!bpf_map_update_elem(&ptregs_size, &key0, &arm64_ptregs_size, BPF_ANY)) {
    DEBUG_PRINT("Failed to update ptregs_size map");
  }

  return arm64_ptregs_size;
}
#endif

// Convert kernel stack pointer to pt_regs pointers at the top-of-stack.
static inline void *get_kernel_stack_ptregs(u64 addr)
{
#if defined(__x86_64__)
  // Fortunately on x86_64 IRQ_STACK_SIZE = THREAD_SIZE. Both depend on
  // CONFIG_KASAN, but that can be assumed off on all production systems.
  // The thread kernel stack should be aligned at least to THREAD_SIZE so the
  // below calculation should yield correct end of stack.
  u64 stack_end = (addr | (THREAD_SIZE - 1)) + 1;
  return (void*)(stack_end - sizeof(struct pt_regs));
#elif defined(__aarch64__)
  u64 stack_end = (addr | (THREAD_SIZE - 1)) + 1;

  u64 ptregs_size = get_arm64_ptregs_size(stack_end);

  return (void*)(stack_end - ptregs_size);
#endif
}

// Extract the usermode pt_regs for given context.
//
// State registers are not touched (get_pristine_per_cpu_record already reset it)
// if something fails.
static inline bool get_usermode_regs(struct bpf_perf_event_data* ctx,
                                     UnwindState *state) {
  if (is_kernel_address(ctx->regs.sp)) {
    // We are in kernel mode stack. There are several different kind kernel
    // stacks. See get_stack_info() in arch/x86/kernel/dumpstack_64.c
    // 1) Exception stack. We don't expect to see these.
    // 2) IRQ stack. Used for hard and softirqs. We can see them in softirq
    //    context. Top-of-stack contains pointer to previous stack (always kernel).
    //    Size on x86_64 is IRQ_STACK_SIZE.
    // 3) Entry stack. This used for kernel code when application does syscall.
    //    Top-of-stack contains user mode pt_regs. Size is THREAD_SIZE.
    //
    // We expect to be on Entry stack, or inside one level IRQ stack which was
    // triggered by executing softirq work on hardirq stack.
    //
    // To optimize code, we always read full pt_regs from the top of kernel stack.
    // The last word of pt_regs is 'ss' which can be used to distinguish if we
    // are on IRQ stack (it's actually the link pointer to previous stack) or
    // entry stack (real SS) depending on if looks like real descriptor.
    struct pt_regs regs;
    if (bpf_probe_read(&regs, sizeof(regs), get_kernel_stack_ptregs(ctx->regs.sp))) {
      return false;
    }
#if defined(__x86_64__)
    if (is_kernel_address(regs.ss)) {
      // ss looks like kernel address. It must be the IRQ stack's link to previous
      // kernel stack. In our case it should be the kernel Entry stack.
      DEBUG_PRINT("Chasing IRQ stack link, ss=0x%lx", regs.ss);
      if (bpf_probe_read(&regs, sizeof(regs), get_kernel_stack_ptregs(regs.ss))) {
        return false;
      }
    }
    // On x86_64 the user mode SS is practically always 0x2B. But this allows
    // for some flexibility. Expect RPL (requested privilege level) to be
    // user mode (3), and to be under max GDT value of 16.
    if ((regs.ss & 3) != 3 || regs.ss >= 16*8) {
      DEBUG_PRINT("No user mode stack, ss=0x%lx", regs.ss);
      return false;
    }
    DEBUG_PRINT("Kernel mode regs (ss=0x%lx)", regs.ss);
#endif
    copy_state_regs(state, &regs);
  } else {
    // User mode code interrupted, registers are available via the ebpf context.
    copy_state_regs(state, (struct pt_regs*)&ctx->regs);
  }

  DEBUG_PRINT("Read regs: pc: %llx sp: %llx fp: %llx",
              state->pc, state->sp, state->fp);
  return true;
}

SEC("perf_event/unwind_native")
int unwind_native(struct bpf_perf_event_data* ctx) {
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  Trace *trace = &record->trace;
  int unwinder;
#pragma unroll
  for (int i = 0; i < NATIVE_FRAMES_PER_PROGRAM; i++) {
    unwinder = PROG_UNWIND_STOP;

    // Unwind native code
    u32 frame_idx = trace->stack_len;
    DEBUG_PRINT("==== unwind_native %d ====", frame_idx);
    increment_metric(metricID_UnwindNativeAttempts);

    // Push frame first. The PC is valid because a text section mapping was found.
    DEBUG_PRINT("Pushing %llx %llx to position %u on stack",
                record->state.text_section_id, record->state.text_section_offset,
                trace->stack_len);
    if (push_native(trace, record->state.text_section_id, record->state.text_section_offset)) {
      DEBUG_PRINT("failed to push native frame");
      return -1;
    }

    // Unwind the native frame using stack deltas. Stop if no next frame.
    if (!unwind_one_frame(trace->pid, frame_idx, &record->state)) {
       break;
    }

    // Continue unwinding
    DEBUG_PRINT(" pc: %llx sp: %llx fp: %llx", record->state.pc, record->state.sp, record->state.fp);
    unwinder = get_next_unwinder(record);
    if (unwinder != PROG_UNWIND_NATIVE) {
      break;
    }
  }

  // Tail call needed for recursion, switching to interpreter unwinder, or reporting
  // trace due to end-of-trace or error. The unwinder program index is set accordingly.
  bpf_tail_call(ctx, &progs, unwinder);
  DEBUG_PRINT("bpf_tail call failed for %d in unwind_native", unwinder);
  return -1;
}

SEC("perf_event/native_tracer_entry")
int native_tracer_entry(struct bpf_perf_event_data* ctx) {
  // Get the PID and TGID register.
  u64 id = bpf_get_current_pid_tgid();
  u64 pid = id >> 32;

  if (pid == 0) {
    return 0;
  }

  DEBUG_PRINT("==== do_perf_event ====");

  // The trace is reused on each call to this function so we have to reset the
  // variables used to maintain state.
  DEBUG_PRINT("Resetting CPU record");
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record)
    return -1;

  Trace *trace = &record->trace;
  trace->pid = pid;

  // Get the kernel mode stack trace first
  trace->kernel_stack_id = bpf_get_stackid(ctx, &kernel_stackmap, BPF_F_REUSE_STACKID);
  DEBUG_PRINT("kernel stack id = %d", trace->kernel_stack_id);

  // Recursive unwind frames
  int unwinder = PROG_UNWIND_STOP;
  if (get_usermode_regs(ctx, &record->state)) {
    if (!pid_information_exists(ctx, pid)) {
      report_new_pid(ctx, pid);
      return 0;
    }
    unwinder = get_next_unwinder(record);
  }
  bpf_tail_call(ctx, &progs, unwinder);

  DEBUG_PRINT("bpf_tail call failed for %d in native_tracer_entry", unwinder);

  return -1;
}
