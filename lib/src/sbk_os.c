/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sbk/sbk_os.h"
#include "sbk/sbk_util.h"

int sbk_os_slot_read(const struct sbk_os_slot *slot, unsigned long off,
                      void *data, size_t len)
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

int sbk_os_slot_prog(const struct sbk_os_slot *slot, unsigned long off,
                      const void *data, size_t len)
{
        SBK_ASSERT(slot);
        SBK_ASSERT(slot->prog);
        SBK_ASSERT(slot->get_size);

        if (off + len > slot->get_size(slot->ctx)) {
                return -SBK_EC_EIO;
        }

        return slot->prog(slot->ctx, off, data, len);
}

int sbk_os_slot_sync(const struct sbk_os_slot *slot)
{
        SBK_ASSERT(slot);
        SBK_ASSERT(slot->sync);
        return slot->sync(slot->ctx);
}

int sbk_os_slot_open(struct sbk_os_slot *slot, unsigned int slot_no)
{
        SBK_ASSERT(slot);
        return sbk_os_slot_init(slot, slot_no);
}

size_t sbk_os_slot_get_sz(const struct sbk_os_slot *slot)
{
        SBK_ASSERT(slot);
        SBK_ASSERT(slot->get_size);
        return slot->get_size(slot->ctx);
}

unsigned long sbk_os_slot_get_sa(const struct sbk_os_slot *slot)
{
        SBK_ASSERT(slot);
        SBK_ASSERT(slot->get_start_address);
        return slot->get_start_address(slot->ctx);
}


bool sbk_os_slot_inrange(const struct sbk_os_slot *slot, unsigned long addr)
{
        SBK_ASSERT(slot);
        SBK_ASSERT(slot->get_start_address);
        SBK_ASSERT(slot->get_size);
        void *ctx = slot->ctx;

        return (addr - slot->get_start_address(ctx)) < slot->get_size(ctx);
}