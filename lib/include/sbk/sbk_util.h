/*
 * Utility macros for sbootkit
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SBK_UTIL_H_
#define SBK_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define SBK_MIN(a, b)             (a < b ? a : b)
#define SBK_MAX(a, b)             (a < b ? b : a)
#define SBK_ALIGNUP(num, align)   (((num) + align) & ~((align)-1))
#define SBK_ALIGNDOWN(num, align) ((num) & ~((align)-1))

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

uint8_t sbk_crc8(uint8_t crc8, void *data, size_t len);

extern void sbk_jump_image(unsigned long address);
extern void sbk_reboot(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SBK_UTIL_H_ */
