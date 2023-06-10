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
        SBK_EC_EINVAL = 22,
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SBK_UTIL_H_ */