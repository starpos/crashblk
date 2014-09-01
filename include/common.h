/**
 * common.h - This is common header for both kernel and userland code.
 */
#ifndef WALB_COMMON_H
#define WALB_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Assert macro, integer typedef, etc.
 */
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/kdev_t.h>
#include "inttypes_kernel.h"
#if defined(DEBUG) || defined(ASSERT_ON)
#define ASSERT(cond) BUG_ON(!(cond))
#else /* WALB_DEBUG */
#define ASSERT(cond)
#endif /* WALB_DEBUG */
#else /* __KERNEL__ */
#include "userland.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#define ASSERT(cond) assert(cond)
#endif /* __KERNEL__ */

#define SRC_FILE (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

/**
 * Function/variable attribute macros.
 */
#define DEPRECATED_ATTR __attribute__((deprecated))
#define UNUSED __attribute__((unused))
#define NOT_YET_IMPLEMENTED __attribute__((warning("NOT YET IMPLEMENTED")))

#ifdef __cplusplus
}
#endif

#endif /* WALB_COMMON_H */
