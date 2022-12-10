// This file contains definitions for the V8 tracer

// V8 constants for the tags. Hard coded to optimize code size and speed.
// They are unlikely to change, and likely require larger modifications on change.

// https://chromium.googlesource.com/v8/v8.git/+/refs/heads/9.2.230/include/v8-internal.h#52
#define SmiTag                  0x0
// https://chromium.googlesource.com/v8/v8.git/+/refs/heads/9.2.230/include/v8-internal.h#54
#define SmiTagMask              0x1
// https://chromium.googlesource.com/v8/v8.git/+/refs/heads/9.2.230/include/v8-internal.h#91
#define SmiTagShift             1
// https://chromium.googlesource.com/v8/v8.git/+/refs/heads/9.2.230/include/v8-internal.h#98
#define SmiValueShift           32
// https://chromium.googlesource.com/v8/v8.git/+/refs/heads/9.2.230/include/v8-internal.h#39
#define HeapObjectTag           0x1
// https://chromium.googlesource.com/v8/v8.git/+/refs/heads/9.2.230/include/v8-internal.h#42
#define HeapObjectTagMask       0x3

// The Trace 'file' field is split to object pointer (aligned to 8 bytes),
// and the zero bits due to alignment are re-used as the following flags.
#define V8_FILE_FLAG_NATIVE     0x1
#define V8_FILE_FLAG_MASK       0x7

// The Trace 'line' field is split to two 32-bit fields: cookie and PC-delta
#define V8_LINE_COOKIE_SHIFT    32
#define V8_LINE_COOKIE_MASK     0xffffffff00000000
#define V8_LINE_DELTA_MASK      0x00000000ffffffff
