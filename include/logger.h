/**
 * logger.h - a simple logger.
 */
#ifndef SIMPLE_LOGGER_H
#define SIMPLE_LOGGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "print.h"

/**
 * Simple logger.
 */
#define LOG_ PRINT_
#define LOGd_ PRINT_
#define LOGi_ PRINT_
#define LOGn_ PRINT_
#define LOGw_ PRINT_
#define LOGe_ PRINT_
#ifdef USE_DYNAMIC_DEBUG
#define LOGd pr_debug
#else
#define LOGd PRINTV_D
#endif
#define LOGi PRINTV_I
#define LOGn PRINTV_N
#define LOGw PRINTV_W
#define LOGe PRINTV_E

#ifdef __cplusplus
}
#endif

#endif /* SIMPLE_LOGGER_H */
