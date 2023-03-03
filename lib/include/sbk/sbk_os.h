/*
 * configuration for sbootkit (routines to be provided by os)
 *
 * Copyright (c) 2021 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SBK_OS_H_
#define SBK_OS_H_

#include <stddef.h>

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
        int (*read)(const void *ctx, unsigned long off, void *data, size_t len);

        /* program to the slot (needs implementation), on devices that
         * require block erase the routine should erase a block when the first
         * byte is written.
         */
        int (*prog)(const void *ctx, unsigned long off, const void *data,
                    size_t len);

        /* sync the slot (needs implementation) */
        int (*sync)(const void *ctx);

        /* get the slot start address (needs implementation) */
        unsigned long (*get_start_address)(const void *ctx);

        /* get the slot size (needs implementation) */
        size_t (*get_size)(const void *ctx);
};

/** @brief sbk_os_slot_init, needs to be provided by os
 *
 * setup sbk_os_slot for usage by bootloader.
 *
 */
extern int (*sbk_os_slot_init)(struct sbk_os_slot *slot, unsigned int slot_no);

/**
 * @brief Interface routines to read/write slots used by bootloader.
 *
 */

/**
 * @brief sbk_os_slot_open
 *
 * open a slot (calls sbk_os_slot_init()), initializes slot
 */
int sbk_os_slot_open(struct sbk_os_slot *slot, unsigned int slot_no);

/**
 * @brief sbk_os_slot_read
 *
 * read from a slot
 */
int sbk_os_slot_read(const struct sbk_os_slot *slot, unsigned long off,
                     void *data, size_t len);

/**
 * @brief sbk_os_slot_program
 *
 * programs to a slot
 */
int sbk_os_slot_prog(const struct sbk_os_slot *slot, unsigned long off,
                     const void *data, size_t len);

/**
 * @brief sbk_os_slot_close
 *
 * closes a slot and ensures all data is written
 */
int sbk_os_slot_close(const struct sbk_os_slot *slot);

/**
 * @brief sbk_os_slot_get_sa
 *
 * get a slot start address
 */
unsigned long sbk_os_slot_get_sa(const struct sbk_os_slot *slot);

/**
 * @brief sbk_os_slot_get_sz
 *
 * get a slot size
 */
size_t sbk_os_slot_get_sz(const struct sbk_os_slot *slot);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SBK_H_ */
