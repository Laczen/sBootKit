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
        SBK_ASSERT(slot->get_size);

        if (off + len > slot->get_size(slot->ctx)) {
                return -SBK_EC_EIO;
        }

        return slot->read(slot->ctx, off, data, len);
}

size_t sbk_slot_get_sz(const struct sbk_slot *slot)
{
        SBK_ASSERT(slot);
        SBK_ASSERT(slot->get_size);
        return slot->get_size(slot->ctx);
}

unsigned long sbk_slot_get_sa(const struct sbk_slot *slot)
{
        SBK_ASSERT(slot);
        SBK_ASSERT(slot->get_start_address);
        return slot->get_start_address(slot->ctx);
}

bool sbk_slot_inrange(const struct sbk_slot *slot, unsigned long addr)
{
        SBK_ASSERT(slot);
        SBK_ASSERT(slot->get_start_address);
        SBK_ASSERT(slot->get_size);
        void *ctx = slot->ctx;

        return (addr - slot->get_start_address(ctx)) < slot->get_size(ctx);
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
        SBK_ASSERT(slot->get_size);

        if (off + len > slot->get_size(slot->ctx)) {
                return -SBK_EC_EIO;
        }

        if (slot->prog == NULL) {
                return 0;
        }

        return slot->prog(slot->ctx, off, data, len);
}