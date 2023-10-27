/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SBK_IMAGE_H_
#define SBK_IMAGE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "sbk/sbk_product.h"

#define SBK_IMAGE_WBS		64
#define SBK_IMAGE_AUTH_TAG	0x7FFF
#define SBK_IMAGE_META_TAG	0x8000

#define SBK_IMAGE_FLAG_CONFIRMED	0x00000001	/* Confirmed image */
#define SBK_IMAGE_FLAG_ENCRYPTED	0x00000010	/* Encrypted image */
#define SBK_IMAGE_FLAG_ZLIB		0x00000020	/* ZLIB compr. image */
#define SBK_IMAGE_FLAG_VCDIFF		0x00000040	/* VCDIFF image */
#define SBK_IMAGE_FLAG_AL_MASK		0xF0000000	/* Alignment mask */
#define SBK_IMAGE_FLAG_AL_SHIFT		28		/* Alignment shift */

#ifndef CONFIG_SBK_IMAGE_AUTHENTICATE
#define CONFIG_SBK_IMAGE_AUTHENTICATE 0	/* Fall back to no authentication */
#endif /* CONFIG_SBK_IMAGE_AUTHENTICATE */

#define SBK_IMAGE_LTKEY_SIZE		32	/* Long term key size */
#define SBK_IMAGE_SALT_SIZE		16	/* NONCE Size */

#define SBK_IMAGE_SIG_SIZE		64	/* Signature size */
#define SBK_IMAGE_SIG_PKHASH_SIZE	32	/* Signature pubkey hash size */
#define SBK_IMAGE_HMAC_SIZE		32	/* HMAC size */

#define SBK_IMAGE_HMAC_CONTEXT 	"SBK HMAC"
#define SBK_IMAGE_CIPH_CONTEXT	"SBK CIPHER"

#define SBK_IMAGE_DEFAULT_KSLOTIDX	0xff

#define SBK_IMAGE_STATE_PDEP	0x00000001 /* Image product dependency mask */
#define SBK_IMAGE_STATE_IDEP    0x00000002 /* Image image dependency mask */
#define SBK_IMAGE_STATE_INRS    0x00000010 /* Image in run slot */
#define SBK_IMAGE_STATE_ICONF   0x00000020 /* Image confirmed */
#define SBK_IMAGE_STATE_SCONF	0x00000021 /* Image in slot confirmed */

#define SBK_IMAGE_STATE_SCONF_MAGIC "CONF"

struct sbk_slot;

struct __attribute__((packed)) sbk_image_rec_hdr {
	uint16_t tag; /* odd-parity tag */
	uint16_t len; /* record length */
};

struct __attribute__((packed)) sbk_image_auth {
	struct sbk_image_rec_hdr rhdr;		/* record tag + length */
	uint8_t hhmac[SBK_IMAGE_HMAC_SIZE];	/* header hmac */
	uint8_t fhmac[SBK_IMAGE_HMAC_SIZE];	/* full hmac (hdr + image) */
	uint8_t sig_pubkey_hash[SBK_IMAGE_SIG_PKHASH_SIZE];
	uint8_t sig[SBK_IMAGE_SIG_SIZE];	/* signature over hhmac + fhmac */
};

struct __attribute__((packed)) sbk_image_meta {
	struct sbk_image_rec_hdr rhdr;	/* record tag + length */
	uint8_t salt[SBK_IMAGE_SALT_SIZE];	/* image salt size */
	uint32_t image_sequence_number; /* increasing anti-rollback number */
	uint32_t image_start_address;
	uint32_t image_flags;           /* flags descr. image properties */
	uint32_t image_size;            /* image size without header */
	uint16_t image_offset;		/* image offset from start of header */
	uint16_t image_dep_tag;		/* first tag descr. image dependencies */
	uint16_t product_dep_tag;	/* first tag descr. product dependency */
	uint16_t other_tag;		/* first tag describing other data */
	struct sbk_version image_version;
};

struct __attribute__((packed)) sbk_image_dep_info {
	struct sbk_image_rec_hdr rhdr;	/* record tag + length */
	struct sbk_version_range vrange;
	uint32_t image_start_address; 	/* dependent image start address */
	uint16_t next_tag;
	uint16_t pad16;
};

struct __attribute__((packed)) sbk_product_dep_info {
	struct sbk_image_rec_hdr rhdr;	/* record tag + length */
	struct sbk_version_range vrange;
	uint32_t product_hash;
	uint16_t next_tag;
	uint16_t pad16;
};

struct sbk_image_state {
	uint32_t state_flags;
	struct sbk_image_meta im;
};

struct sbk_stream_image_ctx {
	struct sbk_slot *slt;
	uint32_t soff;
	uint8_t *sdata;
	bool validate;
};

#define SBK_IMAGE_STATE_PDEP_SET(flags) (flags |= SBK_IMAGE_STATE_PDEP)
#define SBK_IMAGE_STATE_IDEP_SET(flags) (flags |= SBK_IMAGE_STATE_IDEP)
#define SBK_IMAGE_STATE_INRS_SET(flags) (flags |= SBK_IMAGE_STATE_INRS)
#define SBK_IMAGE_STATE_ICONF_SET(flags) (flags |= SBK_IMAGE_STATE_ICONF)
#define SBK_IMAGE_STATE_SCONF_SET(flags) (flags |= SBK_IMAGE_STATE_SCONF)

#define SBK_IMAGE_STATE_PDEP_CLR(flags) (flags &= ~SBK_IMAGE_STATE_PDEP)
#define SBK_IMAGE_STATE_IDEP_CLR(flags) (flags &= ~SBK_IMAGE_STATE_IDEP)
#define SBK_IMAGE_STATE_INRS_CLR(flags) (flags &= ~SBK_IMAGE_STATE_INRS)
#define SBK_IMAGE_STATE_ICONF_CLR(flags) (flags &= ~SBK_IMAGE_STATE_ICONF)
#define SBK_IMAGE_STATE_SCONF_CLR(flags) (flags &= ~SBK_IMAGE_STATE_SCONF)

#define SBK_IMAGE_STATE_COND_IS_SET(flags, CONDITION)				\
	(((flags) & (CONDITION)) == (CONDITION))
#define SBK_IMAGE_STATE_PDEP_IS_SET(flags)					\
	SBK_IMAGE_STATE_COND_IS_SET(flags, SBK_IMAGE_STATE_PDEP)
#define SBK_IMAGE_STATE_IDEP_IS_SET(flags)					\
	SBK_IMAGE_STATE_COND_IS_SET(flags, SBK_IMAGE_STATE_IDEP)
#define SBK_IMAGE_STATE_INRS_IS_SET(flags)					\
	SBK_IMAGE_STATE_COND_IS_SET(flags, SBK_IMAGE_STATE_INRS)
#define SBK_IMAGE_STATE_ICONF_IS_SET(flags)					\
	SBK_IMAGE_STATE_COND_IS_SET(flags, SBK_IMAGE_STATE_ICONF)
#define SBK_IMAGE_STATE_SCONF_IS_SET(flags)					\
	SBK_IMAGE_STATE_COND_IS_SET(flags, SBK_IMAGE_STATE_SCONF)

#define SBK_IMAGE_STATE_CLR_FLAGS(flags) flags = 0U

#define SBK_IMAGE_STATE_IS_RUNNABLE(flags)					\
	SBK_IMAGE_STATE_COND_IS_SET(                                            \
		flags, (SBK_IMAGE_STATE_PDEP | SBK_IMAGE_STATE_IDEP |           \
			SBK_IMAGE_STATE_INRS))

/**
 * @brief sbk_image_read
 *
 * Read data from an image in a slot, this will encrypt the data when the
 * reading is done from a slot where the image can be executed from. As this
 * uses the update key it should only be used in a context where this key is
 * known (e.g. when running as updater).
 *
 * @param slot: pointer to slot where the image resides
 * @return -ERRNO errno code if error, 0 if succesfull
 */
int sbk_image_read(const struct sbk_slot *slot, uint32_t offset, void *data,
		   size_t len);

/**
 * @brief sbk_image_get_version
 *
 * Get the version of an image in a slot
 *
 * @param slot: pointer to slot where the image resides
 * @param version: returns the version as sbk_version
 * @return -ERRNO errno code if error, 0 if succesfull
 */
int sbk_image_get_version(const struct sbk_slot *slot,
			  struct sbk_version *version);

/**
 * @brief sbk_image_get_length
 *
 * Get the length (header + image) of an image in a slot
 *
 * @param slot: pointer to slot where the image resides
 * @param length: returns the length
 * @return -ERRNO errno code if error, 0 if succesfull
 */
int sbk_image_get_length(const struct sbk_slot *slot, size_t *length);

/**
 * @brief sbk_image_get_state
 *
 * Get the state of an image in a slot
 *
 * @param slot: pointer to slot where the image resides
 * @param st: image state
 * @return -ERRNO errno code if error, 0 if succesfull
 */
int sbk_image_get_state(const struct sbk_slot *slot,
			struct sbk_image_state *st);

/**
 * @brief sbk_image_can_run
 *
 * Verifies that an image in slot slt can be started, returns the image state
 * @param slt
 * @param st
 * @return true
 * @return false
 */
bool sbk_image_can_run(const struct sbk_slot *slt, struct sbk_image_state *st);

/**
 * @brief sbk_stream_image_flush
 *
 * Flush the data that is in the buffer of a stream image to a slot.
 *
 * @param ctx: pointer to stream image context
 * @param len: size of data to flush
 * @return -ERRNO errno code if error, 0 if succesfull
 */
int sbk_stream_image_flush(struct sbk_stream_image_ctx *ctx, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SBK_IMAGE_H_*/
