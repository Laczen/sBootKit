/*
 * slot interface for sbootkit
 *
 * Copyright (c) 2021 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SBK_SLOT_H_
#define SBK_SLOT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/**
 * @brief sBootKit relies on the concept of slots, these slots describe any
 * kind of storage solution used for images. 5 basic routines are defined to
 * work with slots: read, prog(ram), close, size and address. Some of these
 * routines are optionally defined. In sBootKit also virtual slots are used as
 * a means to create a receiving slot for direct upload, split slots for
 * swapping images, ...
 *
 */

/**
 * @brief slot interface definition
 *
 */

struct sbk_slot {
	/* opaque context pointer */
	void *ctx;

	/* read from the slot (needs implementation) */
	int (*read)(const void *ctx, uint32_t off, void *data, size_t len);

	/* program to the slot (optional implementation), on devices that
	 * require block erase the routine should erase a block when the first
	 * byte is written.
	 */
	int (*prog)(const void *ctx, uint32_t off, const void *data, size_t len);

	/* close a slot (optional implementation), any required synching of
	 * buffers needs to be performed in this routine
	 */
	int (*close)(const void *ctx);

	/* get the slot size (optional implementation).
	 */
	int (*size)(const void *ctx, size_t *size);

	/* convert off to absolute address (optional implementation)
	 */
	int (*address)(const void *ctx, uint32_t *addr);
};

/**
 * @brief Interface routines to read/write slots used by bootloader.
 *
 */

/**
 * @brief sbk_slot_read
 *
 * read data from a slot
 */
int sbk_slot_read(const struct sbk_slot *slot, uint32_t off, void *data,
		  size_t len);

/**
 * @brief sbk_slot_program
 *
 * program data to a slot
 */
int sbk_slot_prog(const struct sbk_slot *slot, uint32_t off, const void *data,
		  size_t len);

/**
 * @brief sbk_slot_close
 *
 * closes a slot
 */
int sbk_slot_close(const struct sbk_slot *slot);

/**
 * @brief sbk_slot_size
 *
 * get the size of a slot
 */
int sbk_slot_size(const struct sbk_slot *slot, size_t *size);

/**
 * @brief sbk_slot_address
 *
 * translate offset to absolute address
 */
int sbk_slot_address(const struct sbk_slot *slot, uint32_t *address);

/**
 * @brief Slot routines that need to be provided by the os.
 *
 */

extern int sbk_open_sldr_slot(struct sbk_slot *slot);
extern int sbk_open_image_slot(struct sbk_slot *slot, unsigned char idx);
extern int sbk_open_rimage_slot(struct sbk_slot *slot, unsigned char idx);
extern int sbk_open_update_slot(struct sbk_slot *slot, unsigned char idx);
extern int sbk_open_backup_slot(struct sbk_slot *slot, unsigned char idx);
extern int sbk_open_shareddata_slot(struct sbk_slot *slot, unsigned char idx);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SBK_OS_H_ */
