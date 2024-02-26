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

	if ((off + len) > slot->size) {
		return -SBK_EC_EINVAL;
	}

	return slot->read(slot->ctx, off, data, len);
}

int sbk_slot_prog(const struct sbk_slot *slot, uint32_t off, const void *data,
		  size_t len)
{
	SBK_ASSERT(slot);

	if (slot->prog == NULL) {
		return -SBK_EC_ENOTSUP;
	}

	if ((off + len) > slot->size) {
		return -SBK_EC_EINVAL;
	}

	return slot->prog(slot->ctx, off, data, len);
}

int sbk_slot_size(const struct sbk_slot *slot, size_t *size)
{
	SBK_ASSERT(slot);
	SBK_ASSERT(size);

	*size = slot->size;
	return 0;
}

int sbk_slot_address(const struct sbk_slot *slot, uint32_t *address)
{
	SBK_ASSERT(slot);
	SBK_ASSERT(address);

	if (slot->address == NULL) {
		return -SBK_EC_ENOTSUP;
	}

	if (*address > slot->size) {
		return -SBK_EC_EINVAL;
	}
	return slot->address(slot->ctx, address);
}

int sbk_slot_cmd(const struct sbk_slot *slot, enum sbk_slot_cmds cmd,
		 void *data, size_t len)
{
	SBK_ASSERT(slot);

	if (slot->cmd == NULL) {
		return -SBK_EC_ENOTSUP;
	}

	return slot->cmd(slot->ctx, cmd, data, len);
}

int sbk_slot_close(const struct sbk_slot *slot)
{
	SBK_ASSERT(slot);

	if (slot->close == NULL) {
		return 0;
	}

	return slot->close(slot->ctx);
}
