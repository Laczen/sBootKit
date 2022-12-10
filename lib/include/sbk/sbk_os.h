/*
 * configuration for sbootkit (routines to be provided by os)
 *
 * Copyright (c) 2021 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SBK_OS_H_
#define SBK_OS_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief slot interface definition
 *
 */

struct sbk_os_slot {
        /* opaque context pointer */
        void *ctx;

        /* read from the slot (needs implementation) */
        int (*read)(const void *ctx, uint32_t off, void *data, uint32_t len);

        /* program to the slot (needs implementation), on devices that
         * require block erase the routine should erase a block when the first
         * byte is written.
         */
        int (*prog)(const void *ctx, uint32_t off, const void *data, uint32_t len);

        /* sync the slot (needs implementation) */
        int (*sync)(const void *ctx);

        /* get the slot start address (needs implementation) */
        uint32_t (*get_start_address)(const void *ctx);

        /* get the slot size (needs implementation) */
        uint32_t (*get_size)(const void *ctx);
};

/**
 * @brief OS interface routines, need to be provided by os.
 *
 */

/** @brief sbk_os_slot_init
 *
 * setup sbk_os_slot for usage by bootloader.
 *
 */
extern int (*sbk_os_slot_init)(struct sbk_os_slot *slot, uint32_t slot_no);

/** @brief sbk_os_feed_watchdog
 *
 * feed watchdog.
 *
 */
extern int (*sbk_os_feed_watchdog)(void);

/**
 * @brief Interface routines to read/write used by bootloader.
 *
 */

/**
 * @brief sbk_os_slot_open
 *
 * open a slot (calls sbk_os_slot_init()), initializes slot
 */
int sbk_os_slot_open(struct sbk_os_slot *slot, uint32_t slot_no);

/**
 * @brief sbk_os_slot_read
 *
 * read from a slot
 */
int sbk_os_slot_read(const struct sbk_os_slot *slot, uint32_t off,
                     void *data, uint32_t len);

/**
 * @brief sbk_os_slot_program
 *
 * programs to a slot
 */
int sbk_os_slot_prog(const struct sbk_os_slot *slot, uint32_t off,
                     const void *data, uint32_t len);

/**
 * @brief sbk_os_slot_close
 *
 * closes a slot and ensures all data is written
 */
int sbk_os_slot_close(const struct sbk_os_slot *slot);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SBK_H_ */
