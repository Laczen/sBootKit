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
#include "sbk/sbk_slot.h"

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
	SBK_EC_ENOTSUP = 134,
};

struct sbk_key {
	uint8_t *key;
	size_t key_size;
};

void set_sbk_private_key(const struct sbk_key *key);

struct sbk_key *sbk_get_private_key(void);

/* external routines that need to be provided by the os */
extern void sbk_boot_init(void);                   /* os init routine */
extern void sbk_jump_image(unsigned long address); /* */
extern void sbk_boot_prep(unsigned long address);  /* */
extern void sbk_reboot(void);
extern void sbk_watchdog_init(void);
extern void sbk_watchdog_feed(void);

/* slot routines that need to be provided by the os */
extern int sbk_open_sldr_slot(struct sbk_slot *slot);
extern int sbk_open_productdata_slot(struct sbk_slot *slot);
extern int sbk_open_shareddata_slot(struct sbk_slot *slot);
extern int sbk_open_rimage_slot(struct sbk_slot *slot, uint32_t idx);
extern int sbk_open_image_slot(struct sbk_slot *slot, uint32_t idx);
extern int sbk_open_update_slot(struct sbk_slot *slot, uint32_t idx);
extern int sbk_open_backup_slot(struct sbk_slot *slot, uint32_t idx);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SBK_UTIL_H_ */
