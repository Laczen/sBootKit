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

struct __attribute__((packed)) sbk_tlv_product_data { /* product data */
	struct sbk_tlv_rhdr rhdr;
	struct sbk_version version;
	uint8_t guid[SBK_PRODUCT_GUID_SIZE];
	uint32_t serial_no;
};

struct __attribute__((packed)) sbk_tlv_product_name { /* product data */
	struct sbk_tlv_rhdr rhdr;
	char name[];
};

/* Definitions for shared data tlvs */
#define SBK_BOOTINFO_TAG 	0x4000 	/* Boot information tag */
#define SBK_BOOTINFO_CMDNONE	0x00	/* Jump to loader first */
#define SBK_BOOTINFO_CMDSLDR	0x80	/* Jump to loader first */
#define SBK_BOOTINFO_CMDTEST	0x81	/* Allow test image */

struct __attribute__((packed)) sbk_tlv_bootinfo { /* bootinfo */
	struct sbk_tlv_rhdr rhdr;
	uint8_t idx;
	uint8_t cnt;
	uint8_t cmd;
	uint8_t pad0;
};

/* Definitions for image tlvs */
#define SBK_IMAGE_INFO_TAG 0x8000 /* Image info tag */
#define SBK_IMAGE_SFSL_TAG 0x80FD /* Secure First Stage Loader tag */
#define SBK_IMAGE_PUBK_TAG 0x80FE /* Pubkey tag */
#define SBK_IMAGE_SLDR_TAG 0x80FF /* Secure Loader tag */
#define SBK_IMAGE_LEND_TAG 0x0000 /* List end tag */

#define SBK_IMAGE_HASH_SIZE     32 /* (truncated) hash size */
#define SBK_IMAGE_HMAC_SIZE     32 /* HMAC size */
#define SBK_IMAGE_HMAC_KEY_SIZE 44 /* Size of the derived key for hmac */
#define SBK_IMAGE_SALT_SIZE     16 /* Package salt size */
#define SBK_IMAGE_SIGN_SIZE     64 /* Signature size */
#define SBK_IMAGE_PUBK_SIZE     64 /* Public key size */

struct __attribute__((packed)) sbk_tlv_image_info { /* image info */
	struct sbk_tlv_rhdr rhdr;
	uint32_t image_sequence_number;   /* image sequence number */
	struct sbk_version image_version; /* image version */
	uint32_t image_flags;             /* image flags (contains alignment) */
	uint32_t image_size;              /* image size */
	uint32_t image_start_address;     /* image destination address */
	uint16_t image_offset;            /* image offset in package */
	uint16_t idep_tag;                /* first tag with image dependency */
	uint16_t pdep_tag;                /* first tag with product dependency */
	uint16_t other_tag;
	uint8_t image_hash[SBK_IMAGE_HASH_SIZE]; /* (truncated) hash */
};

struct __attribute__((packed)) sbk_tlv_image_dep_info { /* image dependency */
	struct sbk_tlv_rhdr rhdr;
	struct sbk_version_range vrange;
	uint32_t image_start_address; /* dependent image start address */
	uint16_t next_tag;
	uint16_t pad16;
};

struct __attribute__((packed)) sbk_tlv_product_dep_info { /* prod. dependency */
	struct sbk_tlv_rhdr rhdr;
	struct sbk_version_range vrange;
	uint8_t guid[SBK_PRODUCT_GUID_SIZE]; /* product guid */
	uint16_t next_tag;
	uint16_t pad16;
};

struct __attribute__((packed)) sbk_tlv_image_sfsl_auth { /* fsl authent. */
	struct sbk_tlv_rhdr rhdr;
	uint8_t pubkey[SBK_IMAGE_PUBK_SIZE]; /* authent. pubkey */
	uint8_t sign[SBK_IMAGE_SIGN_SIZE];   /* authent. signature */
};

struct __attribute__((packed)) sbk_tlv_image_sfsl_pkhash {
	/* sfsl pubkey hashes (optional): any pubkey that has a hash that
	 * matches one of the listed hashes in considered a valid pubkey.
	 */
	struct sbk_tlv_rhdr rhdr;
	uint8_t pkhash[];
};

struct __attribute__((packed)) sbk_tlv_image_sldr_auth { /* loader authent. */
	struct sbk_tlv_rhdr rhdr;
	uint8_t salt[SBK_IMAGE_SALT_SIZE]; /* authent./cipher salt */
	uint8_t hmac[SBK_IMAGE_HMAC_SIZE]; /* authent. hmac */
};

struct sbk_tlv_erhdr {            /* extended record header */
	struct sbk_tlv_rhdr rhdr; /* record header */
	uint32_t pos;             /* position in slot */
};

struct sbk_slot;

int sbk_tlv_get_erhdr(const struct sbk_slot *slot, uint16_t tag,
		      struct sbk_tlv_erhdr *erhdr);

int sbk_tlv_get_data(const struct sbk_slot *slot, uint16_t tag, void *data,
		     size_t size);

int sbk_tlv_get_product_data(struct sbk_tlv_product_data *data);

int sbk_tlv_get_product_name(char *name, size_t size);

int sbk_tlv_get_bootinfo(struct sbk_tlv_bootinfo *data);

int sbk_tlv_set_bootinfo(struct sbk_tlv_bootinfo *data);

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
