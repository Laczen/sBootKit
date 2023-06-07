/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sbk/sbk_slot.h"
#include "sbk/sbk_util.h"

int sbk_slot_read(const struct sbk_slot *slot, unsigned long off, void *data,
                  size_t len)
{
        SBK_ASSERT(slot);
        SBK_ASSERT(data);
        SBK_ASSERT(slot->read);
        
        if (off + len > slot->size) {
                return -SBK_EC_EIO;
        }

        return slot->read(slot->ctx, off, data, len);
}

int sbk_slot_open(struct sbk_slot *slot)
{
        SBK_ASSERT(slot);

        if (slot->open == NULL) {
                return 0;
        }

        return slot->open(slot->ctx);
}

int sbk_slot_close(const struct sbk_slot *slot)
{
        SBK_ASSERT(slot);

        if (slot->close == NULL) {
                return 0;
        }

        return slot->close(slot->ctx);
}

int sbk_slot_prog(const struct sbk_slot *slot, unsigned long off,
                  const void *data, size_t len)
{
        SBK_ASSERT(slot);

        if (slot->prog == NULL) {
                return 0;
        }

        if (off + len > slot->size) {
                return -SBK_EC_EIO;
        }

        return slot->prog(slot->ctx, off, data, len);
}

int sbk_slot_address(const struct sbk_slot *slot, unsigned long off,
                     unsigned long *address)
{
        SBK_ASSERT(slot);

        if (slot->address == NULL) {
                return -SBK_EC_EINVAL;
        }

        return slot->address(slot->ctx, off, address);
}