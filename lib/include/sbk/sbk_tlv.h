/*
 * TLV (TYPE - LENGTH - VARIABLE) support for sbk
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SBK_TLV_H_
#define SBK_TLV_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

enum sbk_tlv_tags {
        SBK_TLV_TAG_END1 = 0x0000,
        SBK_TLV_TAG_END2 = 0xffff,
};

/* In a tlv area a entry has a type, a length and a value, the value can be
 * found by performing a read after a walk.
 * A entry type of 0x0000 or 0xffff is reserved for internal (end marker) usage
 */

struct __attribute__((__packed__)) sbk_tlv_hdr {
        uint16_t tag;
        uint16_t len;
};

struct __attribute__((__packed__)) sbk_tlv_entry {
        struct sbk_tlv_hdr hdr;
        uint32_t offset;
};

/**
 * @brief tlv API
 * @{
 */

/**
 * @brief sbk_tlv_walk_init
 *
 * initialize tlv entry for walking.
 *
 * @param entry: tlv entry to initialize
 */
void sbk_tlv_walk_init(struct sbk_tlv_entry *entry);

/**
 * @brief sbk_tlv_walk
 *
 * walk over the tlvs.
 *
 * @param entry: returned data
 * @param read_cb: pointer to read routine
 * @param read_cb_ctx: read routine context
 * @retval -ERRNO if error
 * @retval 0 if OK
 */
int sbk_tlv_walk(struct sbk_tlv_entry *entry, int (*read_cb)(const void *ctx,
                 uint32_t offset, void *data, uint32_t len),
                 const void *read_cb_ctx);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SBK_TLV_H_ */
