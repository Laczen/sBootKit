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

#ifdef CONFIG_SBK_UTIL_INCLUDE
#define SBK_STRINGIZE(x) SBK_STRINGIZE2(x)
#define SBK_STRINGIZE2(x) #x
#include SBK_STRINGIZE(CONFIG_SBK_UTIL_INCLUDE)
#endif

#ifndef SBK_LOG_ERR
#define SBK_LOG_ERR(...)
#endif

#ifndef SBK_LOG_WRN
#define SBK_LOG_WRN(...)
#endif

#ifndef SBK_LOG_INF
#define SBK_LOG_INF(...)
#endif

#ifndef SBK_LOG_DBG
#define SBK_LOG_DBG(...)
#endif

#ifndef SBK_ASSERT
#define SBK_ASSERT(...)
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SBK_UTIL_H_ */