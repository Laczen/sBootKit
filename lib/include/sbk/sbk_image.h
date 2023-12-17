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

#define SBK_IMAGE_WBS 64

#define SBK_IMAGE_INFO_TAG 0x8000 /* Image info tag */
#define SBK_IMAGE_SFSL_TAG 0x80FD /* Secure First Stage Loader tag */
#define SBK_IMAGE_PUBK_TAG 0x80FE /* Pubkey tag */
#define SBK_IMAGE_SLDR_TAG 0x80FF /* Secure Loader tag */
#define SBK_IMAGE_LEND_TAG 0x0000 /* List end tag */

#define SBK_IMAGE_FLAG_CONF      0x00000001 /* Confirmed image */
#define SBK_IMAGE_FLAG_CIPH      0x00000010 /* Ciphered image */
#define SBK_IMAGE_FLAG_ZLIB      0x00000020 /* ZLIB compr. image */
#define SBK_IMAGE_FLAG_VCDIFF    0x00000040 /* VCDIFF image */
#define SBK_IMAGE_FLAG_WBS_MASK  0x00FF0000 /* WBS as power of 2 */
#define SBK_IMAGE_FLAG_WBS_SHIFT 16
#define SBK_IMAGE_FLAG_EBS_MASK  0xFF000000 /* EBS as power of 2 */
#define SBK_IMAGE_FLAG_EBS_SHIFT 24

#define SBK_IMAGE_HASH_SIZE 32 /* (truncated) hash size */

#define SBK_IMAGE_HMAC_SIZE     32 /* HMAC size */
#define SBK_IMAGE_HMAC_KEY_SIZE 44 /* Size of the derived key for hmac */
#define SBK_IMAGE_SALT_SIZE     16 /* Package salt size */
#define SBK_IMAGE_HMAC_CONTEXT  "SBK HMAC"
#define SBK_IMAGE_CIPH_CONTEXT  "SBK CIPH"

#define SBK_IMAGE_SIGN_SIZE 64 /* Signature size */
#define SBK_IMAGE_PUBK_SIZE 64 /* Public key size */

#define SBK_IMAGE_FLAG_ISSET(state, flag) (((state) & (flag)) == flag)

#define SBK_IMAGE_STATE_SCONF_MAGIC "CONF"

#define SBK_IMAGE_STATE_FULL 0xFFFFFFFF /* All flags */
#define SBK_IMAGE_STATE_IINF 0x00000001 /* Image info available */
#define SBK_IMAGE_STATE_ICNF 0x00000002 /* Image confirmed */
#define SBK_IMAGE_STATE_INRS 0x00000004 /* Image in run slot */
#define SBK_IMAGE_STATE_PDEP 0x00000008 /* Image product dependency ok */

#define SBK_IMAGE_STATE_BAUT 0x00000010 /* Boot authentication ok */
#define SBK_IMAGE_STATE_LAUT 0x00000020 /* Loader authentication ok */
#define SBK_IMAGE_STATE_VHSH 0x00000040 /* Valid image hash */

#define SBK_IMAGE_STATE_IDEP 0x00000100 /* Image image dependency ok */

#define SBK_IMAGE_STATE_SBOK                                                    \
	(SBK_IMAGE_STATE_IINF | SBK_IMAGE_STATE_PDEP | SBK_IMAGE_STATE_IDEP |   \
	 SBK_IMAGE_STATE_INRS | SBK_IMAGE_STATE_BAUT | SBK_IMAGE_STATE_VHSH)

#define SBK_IMAGE_STATE_LDOK                                                    \
	(SBK_IMAGE_STATE_IINF | SBK_IMAGE_STATE_PDEP | SBK_IMAGE_STATE_IDEP |   \
	 SBK_IMAGE_STATE_LAUT | SBK_IMAGE_STATE_VHSH)

#define SBK_IMAGE_STATE_SET(state, flag)   ((state) |= (flag))
#define SBK_IMAGE_STATE_CLR(state, flag)   ((state) &= ~(flag))
#define SBK_IMAGE_STATE_ISSET(state, flag) (((state) & (flag)) == flag)

struct sbk_slot;

struct __attribute__((packed)) sbk_image_rec_hdr {
	uint16_t tag; /* record tag */
	uint16_t len; /* record length */
};

struct __attribute__((packed)) sbk_image_info { /* image info */
	struct sbk_image_rec_hdr rhdr;
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

struct __attribute__((packed)) sbk_image_dep_info { /* image dependency */
	struct sbk_image_rec_hdr rhdr;
	struct sbk_version_range vrange;
	uint32_t image_start_address; /* dependent image start address */
	uint16_t next_tag;
	uint16_t pad16;
};

struct __attribute__((packed)) sbk_product_dep_info { /* product dependency */
	struct sbk_image_rec_hdr rhdr;
	struct sbk_version_range vrange;
	uint8_t phash[SBK_IMAGE_HASH_SIZE]; /* product hash */
	uint16_t next_tag;
	uint16_t pad16;
};

struct __attribute__((packed)) sbk_image_sfsl_auth { /* fsl authent. */
	struct sbk_image_rec_hdr rhdr;
	uint8_t pubkey[SBK_IMAGE_PUBK_SIZE]; /* authent. pubkey */
	uint8_t sign[SBK_IMAGE_SIGN_SIZE];   /* authent. signature */
};
struct __attribute__((packed)) sbk_image_sfsl_pkhash {
	/* sfsl pubkey hashes (optional): any pubkey that has a hash that
	 * matches one of the listed hashes in considered a valid pubkey.
	 */
	struct sbk_image_rec_hdr rhdr;
	uint8_t pkhash[];
};

struct __attribute__((packed)) sbk_image_sldr_auth { /* loader authent. */
	struct sbk_image_rec_hdr rhdr;
	uint8_t salt[SBK_IMAGE_SALT_SIZE]; /* authent./cipher salt */
	uint8_t hmac[SBK_IMAGE_HMAC_SIZE]; /* authent. hmac */
};

struct sbk_image_state {
	uint32_t state;
	struct sbk_image_info info;
};

bool sbk_image_sfsl_sldr_needed(void);

/**
 * @brief sbk_image_sfsl_state
 *
 * Retrieve the secure first stage loader state of an image in a slot
 *
 * @param slot: the slot to evaluate
 * @param st: image state
 */
void sbk_image_sfsl_state(const struct sbk_slot *slot,
			  struct sbk_image_state *st);

void sbk_image_sldr_state(const struct sbk_slot *slot,
			  struct sbk_image_state *st);

bool sbk_image_sfsl_swap(uint32_t slotnr);

// struct sbk_stream_image_ctx {
// 	struct sbk_slot *slt;
// 	uint32_t soff;
// 	uint8_t *sdata;
// 	bool validate;
// };

// /**
//  * @brief sbk_image_read
//  *
//  * Read data from an image in a slot, this will encrypt the data when the
//  * reading is done from a slot where the image can be executed from. As this
//  * uses the update key it should only be used in a context where this key is
//  * known (e.g. when running as updater).
//  *
//  * @param slot: pointer to slot where the image resides
//  * @return -ERRNO errno code if error, 0 if succesfull
//  */
// int sbk_image_read(const struct sbk_slot *slot, uint32_t offset, void *data,
// 		   size_t len);

// /**
//  * @brief sbk_image_get_version
//  *
//  * Get the version of an image in a slot
//  *
//  * @param slot: pointer to slot where the image resides
//  * @param version: returns the version as sbk_version
//  * @return -ERRNO errno code if error, 0 if succesfull
//  */
// int sbk_image_get_version(const struct sbk_slot *slot,
// 			  struct sbk_version *version);

// /**
//  * @brief sbk_image_get_length
//  *
//  * Get the length (header + image) of an image in a slot
//  *
//  * @param slot: pointer to slot where the image resides
//  * @param length: returns the length
//  * @return -ERRNO errno code if error, 0 if succesfull
//  */
// int sbk_image_get_length(const struct sbk_slot *slot, size_t *length);

// /**
//  * @brief sbk_image_get_state
//  *
//  * Get the state of an image in a slot
//  *
//  * @param slot: pointer to slot where the image resides
//  * @param st: image state
//  * @return -ERRNO errno code if error, 0 if succesfull
//  */
// int sbk_image_get_state(const struct sbk_slot *slot, struct sbk_image_state
// *st);

// /**
//  * @brief sbk_image_can_run
//  *
//  * Verifies that an image in slot slt can be started, returns the image state
//  * @param slt
//  * @param st
//  * @return true
//  * @return false
//  */
// bool sbk_image_can_run(const struct sbk_slot *slt, struct sbk_image_state
// *st);

// /**
//  * @brief sbk_stream_image_flush
//  *
//  * Flush the data that is in the buffer of a stream image to a slot.
//  *
//  * @param ctx: pointer to stream image context
//  * @param len: size of data to flush
//  * @return -ERRNO errno code if error, 0 if succesfull
//  */
// int sbk_stream_image_flush(struct sbk_stream_image_ctx *ctx, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SBK_IMAGE_H_*/
