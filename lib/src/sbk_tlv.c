/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sbk/sbk_tlv.h"
#include "sbk/sbk_util.h"

void sbk_tlv_walk_init(struct sbk_tlv_entry *entry)
{
        entry->hdr.tag = SBK_TLV_TAG_END1;
        entry->hdr.len = 0U;
        entry->offset = 0U;
}

int sbk_tlv_walk(struct sbk_tlv_entry *entry, int (*read_cb)(const void *ctx,
                 uint32_t offset, void *data, uint32_t len),
                 const void *read_cb_ctx)
{
        int rc;
        
        entry->offset += entry->hdr.len;
        rc = read_cb(read_cb_ctx, entry->offset, &entry->hdr,
                     sizeof(entry->hdr));
        
        if ((rc != 0) || (entry->hdr.tag == SBK_TLV_TAG_END1) ||
            (entry->hdr.tag == SBK_TLV_TAG_END2)) {
                return -SBK_EC_ENOENT;
        }

        entry->offset += sizeof(entry->hdr);
        return 0;
}