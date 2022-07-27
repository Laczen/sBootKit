/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sbk/sbk_os.h"

#define ASSERT(expr)

int sbk_os_slot_rread(const struct sbk_os_slot *slot, uint32_t off,
                      void *data, uint32_t len)
{
        ASSERT(slot);
        ASSERT(data);
        ASSERT(slot->rread);
        return slot->rread(slot, off, data, len);
}

int sbk_os_slot_rprog(const struct sbk_os_slot *slot, uint32_t off,
                      const void *data, uint32_t len)
{
        ASSERT(slot);
        ASSERT(slot->rprog);
        return slot->rprog(slot, off, data, len);
}

int sbk_os_slot_uread(const struct sbk_os_slot *slot, uint32_t off,
                      void *data, uint32_t len)
{
        ASSERT(slot);
        ASSERT(data);
        ASSERT(slot->uread);
        return slot->uread(slot, off, data, len);
}

int sbk_os_store_uprog(const struct sbk_os_slot *slot, uint32_t off,
                      const void *data, uint32_t len)
{
        ASSERT(slot);
        if (slot->uprog != NULL) {
                return slot->uprog(slot, off, data, len);
        }
        
        return 0;
}

int sbk_os_slot_close(const struct sbk_os_slot *slot)
{
        ASSERT(slot);
        ASSERT(slot->close);
        return slot->close(slot);
}

int sbk_os_slot_open(struct sbk_os_slot *slot, uint32_t slot_no)
{
        ASSERT(slot);
        slot = sbk_os_get_slot(slot_no);
        return 0;
}