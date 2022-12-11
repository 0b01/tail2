#ifndef OPTI_BPFDEFS_H
#define OPTI_BPFDEFS_H

#include "bpf_map.h"
#include "inttypes.h"

#ifdef TESTING
  // needed for usermode test builds
  #include <stdint.h>
  #include <unistd.h> // pid_t
  #include <linux/types.h>

  #define SEC(NAME)
  #define PAGE_SIZE 4096
#endif

#if defined(TESTING_COREDUMP)

  // utils/coredump uses CGO to build the eBPF code. Provide here the glue to
  // dispatch the BPF API to helpers implemented in ebpfhelpers.go.
  #include <linux/bpf.h>    // BPF_* defines
  #include "tests/kernel.h" // struct pt_regs

  #define printt(fmt, ...) bpf_log(fmt, ##__VA_ARGS__)
  #define DEBUG_PRINT(fmt, ...) bpf_log(fmt, ##__VA_ARGS__)
  #define OPTI_DEBUG

  struct bpf_perf_event_data {
      struct pt_regs regs;
  };

  // BPF helpers. Mostly stubs to dispatch the call to Go code with the context ID.
  int bpf_tail_call(void *ctx, bpf_map_def *map, int index);
  unsigned long long bpf_ktime_get_ns(void);
  int bpf_get_current_comm(void *, int);

  static inline int bpf_probe_read(void *buf, u32 sz, const void *ptr) {
    int __bpf_probe_read(u64, void *, u32, const void *);
    return __bpf_probe_read(__cgo_ctx->id, buf, sz, ptr);
  }

  static inline u64 bpf_get_current_pid_tgid(void) {
    return __cgo_ctx->id;
  }

  static inline void *bpf_map_lookup_elem(bpf_map_def *map, const void *key) {
    void *__bpf_map_lookup_elem(u64, bpf_map_def *, const void *);
    return __bpf_map_lookup_elem(__cgo_ctx->id, map, key);
  }

  static inline int bpf_map_update_elem(bpf_map_def *map, const void *key, const void *val,
      u64 flags) {
    return -1;
  }

  static inline int bpf_perf_event_output(void *ctx, bpf_map_def *mapdef, unsigned long long flags,
      void *data, int size) {
    return 0;
  }

  static inline int bpf_get_stackid(void *ctx, bpf_map_def *map, u64 flags) {
    return -1;
  }

#elif defined(TESTING)

  // test-ebpf-userspace test build
  #include "tests/bpf.h"
  #include "tests/log.h"

  #define printt(fmt, ...) log_infof(fmt "\n", ##__VA_ARGS__)
  #define DEBUG_PRINT(fmt, ...) log_infof(fmt "\n", ##__VA_ARGS__)

#else // TESTING || TESTING_COREDUMP

// Native eBPF build

#include <linux/kconfig.h> // atomic64_t
// Linux 5.4 introduces asm_inline which clang cannot deal with. Disable it.
#undef CONFIG_CC_HAS_ASM_INLINE
#include <uapi/linux/bpf_perf_event.h>

#include <linux/bpf.h>

// definitions of bpf helper functions we need, as found in
// https://elixir.bootlin.com/linux/v4.11/source/samples/bpf/bpf_helpers.h

static void *(*bpf_map_lookup_elem)(void *map, void *key) =
    (void *)BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value, u64 flags) =
    (void *)BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) =
    (void *)BPF_FUNC_map_delete_elem;
static int (*bpf_probe_read)(void *dst, int size, const void *unsafe_ptr) =
    (void *)BPF_FUNC_probe_read;
static unsigned long long (*bpf_ktime_get_ns)(void) =
    (void *)BPF_FUNC_ktime_get_ns;
static unsigned long long (*bpf_get_current_pid_tgid)(void) =
    (void *)BPF_FUNC_get_current_pid_tgid;
static int (*bpf_get_current_comm)(void *buf, int buf_size) =
    (void *) BPF_FUNC_get_current_comm;
static void (*bpf_tail_call)(void *ctx, void *map, int index) =
    (void *)BPF_FUNC_tail_call;
static unsigned long long (*bpf_get_current_task)(void) =
    (void *)BPF_FUNC_get_current_task;
static int (*bpf_perf_event_output)(void *ctx, void *map, unsigned long long flags, void *data, int size) =
    (void *)BPF_FUNC_perf_event_output;
static int (*bpf_get_stackid)(void *ctx, void *map, u64 flags) =
    (void *)BPF_FUNC_get_stackid;

__attribute__ ((format (printf, 1, 3)))
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
    (void *)BPF_FUNC_trace_printk;

// The sizeof in bpf_trace_printk() must include \0, else no output
// is generated. The \n is not needed on 5.8+ kernels, but definitely on
// 5.4 kernels.
#define printt(fmt, ...)                                       \
  ({                                                           \
    const char ____fmt[] = fmt "\n";                           \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })

#ifdef OPTI_DEBUG
  #define DEBUG_PRINT(fmt, ...) printt(fmt, ##__VA_ARGS__);

  // Sends `SIGTRAP` to the current task, killing it and capturing a coredump.
  //
  // Only use this in code paths that you expect to be hit by a very specific process that you
  // intend to debug. Placing it into frequently taken code paths might otherwise take down
  // important system processes like sshd or your window manager. For frequently taken cases,
  // prefer using the `DEBUG_CAPTURE_COREDUMP_IF_TGID` macro.
  //
  // This macro requires linking against kernel headers >= 5.6.
  #define DEBUG_CAPTURE_COREDUMP()                                                          \
    ({                                                                                      \
      /* We don't define `bpf_send_signal_thread` globally because it requires a      */    \
      /* rather recent kernel (>= 5.6) and otherwise breaks builds of older versions. */    \
      long (*bpf_send_signal_thread)(u32 sig) = (void *)BPF_FUNC_send_signal_thread;        \
      bpf_send_signal_thread(SIGTRAP);                                                      \
    })

  // Like `DEBUG_CAPTURE_COREDUMP`, but only coredumps if the current task is a member of the given
  // thread group ID ("process").
  #define DEBUG_CAPTURE_COREDUMP_IF_TGID(tgid)                                              \
    ({                                                                                      \
      if (bpf_get_current_pid_tgid() >> 32 == (tgid)) {                                     \
        DEBUG_PRINT("coredumping process %d", (tgid));                                      \
        DEBUG_CAPTURE_COREDUMP();                                                           \
      }                                                                                     \
    })
#else
  #define DEBUG_PRINT(fmt, ...)
  #define DEBUG_CAPTURE_COREDUMP()
  #define DEBUG_CAPTURE_COREDUMP_IF_TGID(tgid)
#endif

#define SEC(NAME) __attribute__((section(NAME), used))

#endif // !(TESTING || TESTING_COREDUMP)

#define ATOMIC_ADD(ptr, n) __sync_fetch_and_add(ptr, n)

#endif // OPTI_BPFDEFS_H
