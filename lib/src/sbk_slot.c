/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sbk/sbk_slot.h"
#include "sbk/sbk_util.h"
#include "sbk/sbk_log.h"

int sbk_slot_read(const struct sbk_slot *slot, uint32_t off, void *data,
		  size_t len)
{
	SBK_ASSERT(slot);
	SBK_ASSERT(data);
	SBK_ASSERT(slot->read);

	return slot->read(slot->ctx, off, data, len);
}

int sbk_slot_close(const struct sbk_slot *slot)
{
	SBK_ASSERT(slot);

	if (slot->close == NULL) {
		return 0;
	}

	return slot->close(slot->ctx);
}

int sbk_slot_prog(const struct sbk_slot *slot, uint32_t off, const void *data,
		  size_t len)
{
	SBK_ASSERT(slot);

	if (slot->prog == NULL) {
		return 0;
	}

	return slot->prog(slot->ctx, off, data, len);
}

int sbk_slot_size(const struct sbk_slot *slot, size_t *size)
{
	SBK_ASSERT(slot);

	if ((slot->size == NULL) || (size == NULL)) {
		return -SBK_EC_EINVAL;
	}

	return slot->size(slot->ctx, size);
}

int sbk_slot_address(const struct sbk_slot *slot, uint32_t *address)
{
	SBK_ASSERT(slot);

	if ((slot->address == NULL) || (address == NULL)) {
		return -SBK_EC_EINVAL;
	}

	return slot->address(slot->ctx, address);
}
