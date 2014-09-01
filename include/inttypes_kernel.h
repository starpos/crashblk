/**
 * inttypes_kernel.h - Int types for kernel code.
 */
#ifndef INT_TYPES_KERNEL_H
#define INT_TYPES_KERNEL_H

#ifdef CONFIG_64BIT
#define __PRI64_PREFIX "ll" /* u64 is unsigned long long even if 64bit. */
#else
#define __PRI64_PREFIX "ll"
#endif

#define PRId8  "d"
#define PRId16 "d"
#define PRId32 "d"
#define PRId64 __PRI64_PREFIX "d"

#define PRIu8  "u"
#define PRIu16 "u"
#define PRIu32 "u"
#define PRIu64 __PRI64_PREFIX "u"

#define PRIx8  "x"
#define PRIx16 "x"
#define PRIx32 "x"
#define PRIx64 __PRI64_PREFIX "x"

#endif /* INT_TYPES_KERNEL_H */
