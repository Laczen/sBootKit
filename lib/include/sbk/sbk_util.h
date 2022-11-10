/*
 * Utility macros for sbootkit
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SBK_UTIL_H_
#define SBK_UTIL_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SBK_MIN(a,b) (a < b ? a : b)
#define SBK_MAX(a,b) (a < b ? b : a)
#define SBK_ALIGNUP(num, align) (((num) + align) & ~((align) - 1))
#define SBK_ALIGNDOWN(num, align) ((num) & ~((align) - 1))

/**
 * @brief Enumerate Error Return Values
 *
 */
enum sbk_error_codes {
        SBK_EC_ENOENT = 2,
        SBK_EC_EIO = 5,
        SBK_EC_EFAULT = 14,
};

/**
 * @brief Enumerate log codes
 *
 */
enum sbk_log_codes {
        SBK_LOG_LEVEL_OFF = 0,
        SBK_LOG_LEVEL_ERROR = 1,
        SBK_LOG_LEVEL_WARN = 1,
        SBK_LOG_LEVEL_INFO = 2,
        SBK_LOG_LEVEL_DEBUG = 3,
};

#ifndef SBK_LOG
#define SBK_LOG(...)
#endif

#ifndef SBK_LOG_LEVEL
#define SBK_LOG_LEVEL SBK_LOG_LEVEL_INFO
#endif

#define SBK_LOG_ERR(_fmt, ...)                                                 \
do {                                                                           \
        if (SBK_LOG_LEVEL >= SBK_LOG_LEVEL_ERROR) {                            \
                SBK_LOG("ERR:" # _fmt, __VA_ARGS__);                           \
        }                                                                      \
} while (0)

#define SBK_LOG_WRN(_fmt, ...)                                                 \
do {                                                                           \
        if (SBK_LOG_LEVEL >= SBK_LOG_LEVEL_WARN) {                             \
                SBK_LOG("WRN:" # _fmt, __VA_ARGS__);                           \
        }                                                                      \
} while (0)

#define SBK_LOG_INF(_fmt, ...)                                                 \
do {                                                                           \
        if (SBK_LOG_LEVEL >= SBK_LOG_LEVEL_INFO) {                             \
                SBK_LOG("INF:" # _fmt, __VA_ARGS__);                           \
        }                                                                      \
} while (0)

#define SBK_LOG_DBG(_fmt, ...)                                                 \
do {                                                                           \
        if (SBK_LOG_LEVEL >= SBK_LOG_LEVEL_DEBUG) {                            \
                SBK_LOG("DBG:" # _fmt, __VA_ARGS__);                           \
        }                                                                      \
} while (0)

#define SBK_ASSERT(EXPR)                                                       \
do {                                                                           \
        if ((SBK_LOG_LEVEL >= SBK_LOG_LEVEL_DEBUG) && (!EXPR)) {               \
                SBK_LOG("ASSERT for %s at %s", #EXPR, __func__);               \
                while (1);                                                     \
        }                                                                      \
} while (0)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SBK_UTIL_H_ */