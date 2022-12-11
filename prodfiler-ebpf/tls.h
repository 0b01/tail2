#ifndef OPTI_TLS_H
#define OPTI_TLS_H

#include "bpfdefs.h"

// tls_read reads from the TLS location associated with the provided key.
static inline __attribute__((__always_inline__))
int tls_read(const void *tls_base, int key, void **out) {
  // This assumes autoTLSkey < 32, which means that the TLS is stored in
  //   pthread->specific_1stblock[autoTLSkey]
  // 'struct pthread' is not in the public API so we have to hardcode
  // the offsets here
  // NOTE: Current works with glibc only.
  // 0x10 is sizeof(pthread_key_data)
  // 0x8 is offsetof(struct pthread_key_data, data)
#if defined(__x86_64__)
  // 0x310 is offsetof(struct pthread, specific_1stblock),
  const void *tls_addr = tls_base + 0x310 + key * 0x10 + 0x08;
#elif defined(__aarch64__)
  // 0x6f0 is sizeof(struct pthread); on arm the tls_base points to byte after the struct
  // 0x110 is offsetof(struct pthread, specific_1stblock)
  const void *tls_addr = tls_base - 0x6f0 + 0x110 + key * 0x10 + 0x08;
#endif

  DEBUG_PRINT("readTLS key %d from address 0x%lx", key, (unsigned long) tls_addr);
  if (bpf_probe_read(out, sizeof(*out), tls_addr)) {
    DEBUG_PRINT("Failed to read TLS from 0x%lx", (unsigned long) tls_addr);
    increment_metric(metricID_UnwindErrBadTLSAddr);
    return -1;
  }

  return 0;
}

// tls_get_base looks up the base address for TLS variables (TPBASE).
static inline __attribute__((__always_inline__))
int tls_get_base(struct pt_regs *ctx, void **tls_base) {
#ifdef TESTING_COREDUMP
  *tls_base = (void *) __cgo_ctx->tp_base;
  return 0;
#else
  u32 key = 0;
  SystemConfig* syscfg = bpf_map_lookup_elem(&system_config, &key);
  if (!syscfg) {
    // Unreachable: array maps are always fully initialized.
    return -1;
  }

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // We need to read task->thread.fsbase (on x86_64), but we can't do so because
  // we might have been compiled with different kernel headers, so the struct layout
  // is likely to be different.
  // syscfg->tpbase_offset is populated with the offset of `fsbase` or equivalent field
  // relative to a `task_struct`, so we use that instead.
  void *tpbase_ptr = ((char *)task) + syscfg->tpbase_offset;
  if (bpf_probe_read(tls_base, sizeof(void *), tpbase_ptr)) {
    DEBUG_PRINT("Failed to read tpbase value");
    increment_metric(metricID_UnwindErrBadTPBaseAddr);
    return -1;
  }

  return 0;
#endif
}

#endif // OPTI_TLS_H
