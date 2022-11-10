/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sbk/sbk_os.h"
#include "sbk/sbk_util.h"

int sbk_os_slot_read(const struct sbk_os_slot *slot, uint32_t off,
                      void *data, uint32_t len)
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

int sbk_os_slot_prog(const struct sbk_os_slot *slot, uint32_t off,
                      const void *data, uint32_t len)
{
        SBK_ASSERT(slot);
        SBK_ASSERT(slot->prog);
        SBK_ASSERT(slot->get_size);

        if (off + len > slot->get_size(slot->ctx)) {
                return -SBK_EC_EIO;
        }

        return slot->prog(slot->ctx, off, data, len);
}

int sbk_os_slot_open(struct sbk_os_slot *slot, uint32_t slot_no)
{
        SBK_ASSERT(slot);
        return sbk_os_slot_init(slot, slot_no);
}

int sbk_os_slot_close(const struct sbk_os_slot *slot)
{
        SBK_ASSERT(slot);
        SBK_ASSERT(slot->sync);
        return slot->sync(slot->ctx);
}

bool sbk_os_slot_address_in_slot(const struct sbk_os_slot *slot,
                                 const uint32_t address)
{
        SBK_ASSERT(slot);
        SBK_ASSERT(slot->get_start_address);
        SBK_ASSERT(slot->get_size);

        const uint32_t slot_start = slot->get_start_address(slot);
        const uint32_t slot_end = slot_start + slot->get_size(slot);

        if ((address < slot_start) || (address > slot_end)) {
                return false;
        }

        return true;
}