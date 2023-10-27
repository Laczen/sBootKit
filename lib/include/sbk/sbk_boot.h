/*
 * boot interface for sbootkit
 *
 * Copyright (c) 2021 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SBK_BOOT_H_
#define SBK_BOOT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief sbk_boot
 *
 * boot the image in slot idx, use alternative image (selects newest) when
 * requested, do upgrade when requested.
 *
 * @param idx: slot idx to boot
 * @param alt: auto select alternative
 * @param upg: upgrade before boot
 */
void sbk_boot(uint8_t idx, bool alt, bool upg);

/* jumping to a image at address should be provided by the os */
extern void sbk_jump_image(unsigned long address);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SBK_BOOT_H_ */
