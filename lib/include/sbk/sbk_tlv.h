/*
 * tlv (tag length value) record interface for sbootkit
 *
 * Copyright (c) 2021 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SBK_TLV_H_
#define SBK_TLV_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "sbk/sbk_util.h" /* definition of sbk_version */

/**
 * @brief sBootKit uses tag length value (TLV) records to store data in slots.
 *
 * TLV's have the attribute packed and look like:
 * struct __attribute__((packed)) sbk_tlv_xxx {
 *      struct sbk_tlv_rhdr rhdr; // header containing tag and length
 *      ... data;
 * };
 *
 *
 */

#define SBK_MAX_TLV_SIZE 0x8000

struct __attribute__((packed)) sbk_version {
	uint8_t major;
	uint8_t minor;
	uint16_t revision;
};

struct __attribute__((packed)) sbk_version_range {
	struct sbk_version min_version;
	struct sbk_version max_version;
};

struct __attribute__((packed)) sbk_tlv_rhdr { /* record header */
	uint16_t tag;                         /* record tag */
	uint16_t len;                         /* record length */
};

/* Definitions for product tlvs */
#define SBK_PRODUCT_DATA_TAG 0x2000 /* Product data tag */
#define SBK_PRODUCT_NAME_TAG 0x2001 /* Product name tag */
#define SBK_PRODUCT_GUID_SIZE 16

struct __attribute__((packed)) sbk_product_data { /* product data */
	struct sbk_version version;
	uint8_t guid[SBK_PRODUCT_GUID_SIZE];
	uint32_t serial_no;
};

/* Definitions for shared data tlvs */
#define SBK_BOOTINFO_TAG 	0x4000 	/* Boot information tag */

struct __attribute__((packed)) sbk_bootinfo { /* bootinfo */
	uint8_t idx;
	uint8_t cnt;
	uint8_t pad0;
	uint8_t pad1;
};

struct sbk_tlv_info {			/* tlv data info */
	const struct sbk_slot *slot;	/* tlv slot */
	uint32_t pos;			/* position in slot */
	size_t size;			/* tlv size */
};

struct sbk_slot;

bool sbk_tlv_tag_cb(const struct sbk_slot *slot, uint16_t tag,
		   bool (*cb)(const struct sbk_tlv_info *info, void *cb_arg),
		   void *cb_arg);

int sbk_tlv_get_pos(const struct sbk_slot *slot, uint16_t tag, uint32_t *pos);

int sbk_tlv_get_data(const struct sbk_slot *slot, uint16_t tag, void *data,
		     size_t size);

int sbk_tlv_get_product_data(struct sbk_product_data *data);

int sbk_tlv_get_product_name(char *name, size_t size);

int sbk_tlv_get_bootinfo(struct sbk_bootinfo *data);

int sbk_tlv_set_bootinfo(struct sbk_bootinfo *data);

/**
 * @brief sbk_version_in_range
 *
 * Checks if version is inside specified range
 *
 * @param ver: version
 * @param range: range
 * @retval true if version is in range, false otherwise
 */
bool sbk_version_in_range(const struct sbk_version *ver,
			  const struct sbk_version_range *range);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SBK_TLV_H_ */
