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
 * kind of storage solution used for images. 4 basic routines are defined to
 * work with slots: read, prog(ram), ioctl, close. Some of these
 * routines are optionally defined. In sBootKit also virtual slots are used as
 * a means to create a receiving slot for direct upload, split slots for
 * swapping images, ...
 *
 */

enum sbk_slot_ioctl_cmd {
	SBK_SLOT_IOCTL_INVALID = 0,
	SBK_SLOT_IOCTL_GET_SIZE = 1,
	SBK_SLOT_IOCTL_GET_ADDRESS = 2,
	SBK_SLOT_IOCTL_GET_ERASE_BLOCK_SIZE = 3,
	SBK_SLOT_IOCTL_GET_WRITE_BLOCK_SIZE = 4,
};

/**
 * @brief slot interface definition
 *
 */

struct sbk_slot {
	/* opaque context pointer */
	void *ctx;

	/* read data from slot (needs implementation) */
	int (*read)(const void *ctx, uint32_t off, void *data, size_t len);

	/* program data to slot (optional implementation), when calling the
	 * prog routine on a backend that needs erase before programming the
	 * routine should erase before programming. */
	int (*prog)(const void *ctx, uint32_t off, const void *data, size_t len);

	/* get/set properties of the slot. */
	int (*ioctl)(const void *ctx, enum sbk_slot_ioctl_cmd cmd, void *data,
		     size_t len);

	/* close a slot (optional implementation), any required synching of
	 * buffers needs to be performed in this routine
	 */
	int (*close)(const void *ctx);
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
 * @brief sbk_slot_ioctl
 *
 * Get or set slot properties
 */
int sbk_slot_ioctl(const struct sbk_slot *slot, enum sbk_slot_ioctl_cmd cmd,
		   void *data, size_t len);

/**
 * @brief sbk_slot_close
 *
 * closes a slot
 */
int sbk_slot_close(const struct sbk_slot *slot);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SBK_SLOT_H_ */
