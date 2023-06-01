/*
 * slot interface for sbootkit
 *
 * Copyright (c) 2021 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SBK_SLOT_H_
#define SBK_SLOT_H_

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief slot interface definition
 *
 */

struct sbk_slot {
        /* opaque context pointer */
        void *ctx;

        /* slot size */
        size_t size;

        /* read from the slot (needs implementation) */
        int (*read)(const void *ctx, unsigned long off, void *data, size_t len);

        /* open a slot (optional implementation), any required initialisation
         * needs to be performed in this routine
         */
        int (*open)(const void *ctx);

        /* close a slot (optional implementation), any required synching of
         * buffers needs to be performed in this routine
         */
        int (*close)(const void *ctx);

        /* program to the slot (optional implementation), on devices that
         * require block erase the routine should erase a block when the first
         * byte is written.
         */
        int (*prog)(const void *ctx, unsigned long off, const void *data,
                    size_t len);

        /* convert off to absolute address (optional implementation) */
        int (*address)(const void *ctx, unsigned long off, unsigned long *addr);
};

/** @brief sbk_slot_get, needs to be provided by os
 *
 * retrieve a physical slot for usage by bootloader, the slots are considered
 * indexed by a slot number (slot_no).
 * @param: slot: pointer to the slot,
 * @param: slot_no: slot index,
 * @retval: 0 if succesful, any nonzero value if slot_no exceeds number of slots
 *
 */
extern int (*sbk_slot_get)(struct sbk_slot *slot, unsigned int slot_no);

/**
 * @brief Interface routines to read/write slots used by bootloader.
 *
 */

/**
 * @brief sbk_slot_open
 *
 * open (initialize) a slot
 */
int sbk_slot_open(struct sbk_slot *slot);

/**
 * @brief sbk_slot_read
 *
 * read data from a slot
 */
int sbk_slot_read(const struct sbk_slot *slot, unsigned long off, void *data,
                  size_t len);

/**
 * @brief sbk_slot_program
 *
 * program data to a slot
 */
int sbk_slot_prog(const struct sbk_slot *slot, unsigned long off,
                  const void *data, size_t len);

/**
 * @brief sbk_slot_close
 *
 * closes a slot
 */
int sbk_slot_close(const struct sbk_slot *slot);

/**
 * @brief sbk_slot_address
 *
 * translate offset to absolute address
 */
int sbk_slot_address(const struct sbk_slot *slot, unsigned long off,
                     unsigned long *address);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SBK_OS_H_ */
