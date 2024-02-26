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

#define SBK_IMAGE_WBS		64
#define SBK_SHA256_SIZE		32
#define SBK_P256_SIGN_SIZE	64
#define SBK_P256_PUBK_SIZE	64
#define SBK_ED25519_SIGN_SIZE	64
#define SBK_ED25519_PUBK_SIZE	32
#define SBK_CIPHER_SALT_SIZE	16

#define SBK_IMAGE_CIPH_CONTEXT "SBK CIPH"

/* Definitions for image tlvs */
#define SBK_IMAGE_INFO_TAG	0x8000 /* Image info tag */
#define SBK_IMAGE_TLVF_TAG	0x80BF /* Image tlv filler tag */
#define SBK_IMAGE_SSLC_TAG0	0x80C0 /* Second Stage Loader cipher tag */
#define SBK_IMAGE_SSLI_TAG0	0x80D0 /* Second Stage Loader integrity tag */
#define SBK_IMAGE_FSLI_TAG0	0x80F0 /* First Stage Loader integrity tag */
#define SBK_IMAGE_LEND_TAG	0x0000 /* List end tag */

#define SBK_IMAGE_CIPK_SIZE	44 /* Size of the derived key for cipher */

#define SBK_IMAGE_FLAG_TEST      0x00000001 /* Test image */
#define SBK_IMAGE_FLAG_ZLIB      0x00000020 /* ZLIB compr. image */
#define SBK_IMAGE_FLAG_VCDIFF    0x00000040 /* VCDIFF image */

struct __attribute__((packed)) sbk_image_info { /* image info */
	uint32_t image_sequence_number;   /* image sequence number */
	struct sbk_version image_version; /* image version */
	uint32_t image_flags;             /* image flags (contains alignment) */
	uint32_t image_size;              /* image size */
	uint32_t image_start_address;     /* image destination address */
	uint16_t image_offset;            /* image offset in package */
	uint16_t idep_tag;                /* first tag with image dependency */
	uint16_t pdep_tag;                /* first tag with product dependency */
	uint16_t other_tag;
	uint8_t sha256[SBK_SHA256_SIZE]; /* hash */
};

struct __attribute__((packed)) sbk_image_dep_info { /* image dependency */
	struct sbk_version_range vrange;
	uint32_t image_start_address; /* dependent image start address */
	uint16_t next_tag;
	uint16_t pad16;
};

struct __attribute__((packed)) sbk_product_dep_info { /* prod. dependency */
	struct sbk_version_range vrange;
	uint8_t guid[SBK_PRODUCT_GUID_SIZE]; /* product guid */
	uint16_t next_tag;
	uint16_t pad16;
};

struct __attribute__((packed)) sbk_image_ssl_cipher0 {
	uint8_t salt[SBK_CIPHER_SALT_SIZE]; /* cipher salt */
};

struct __attribute__((packed)) sbk_image_ssl_p256_int {
	uint8_t sign[SBK_P256_SIGN_SIZE];   /* ssl p256 signature */
};

struct __attribute__((packed)) sbk_image_ssl_ed25519_int {
	uint8_t sign[SBK_ED25519_SIGN_SIZE];   /* ssl ed25519 signature */
};

struct __attribute__((packed)) sbk_image_fsl_int {
	uint8_t sha256[SBK_SHA256_SIZE]; /* fsl sha of header */
};

#define SBK_IMAGE_FLAG_ISSET(state, flag) (((state) & (flag)) == flag)

#define SBK_IMAGE_STATE_FULL 0xFFFFFFFF /* All flags */
#define SBK_IMAGE_STATE_IINF 0x00000001 /* Image info available */
#define SBK_IMAGE_STATE_INDS 0x00000002 /* Image in destination slot */
#define SBK_IMAGE_STATE_IDEP 0x00000004 /* Image image dependency ok */
#define SBK_IMAGE_STATE_PDEP 0x00000008 /* Image product dependency ok */

#define SBK_IMAGE_STATE_FSLI 0x00000010 /* first stage loader integrity ok */
#define SBK_IMAGE_STATE_SSLI 0x00000020 /* second stage loader integrity ok */
#define SBK_IMAGE_STATE_IMGI 0x00000040 /* image integrity ok */

#define SBK_IMAGE_STATE_TEST 0x00000100 /* Test image */

#define SBK_IMAGE_STATE_FSLOK                                                   \
	(SBK_IMAGE_STATE_IINF | SBK_IMAGE_STATE_PDEP | SBK_IMAGE_STATE_IDEP |   \
	 SBK_IMAGE_STATE_INDS | SBK_IMAGE_STATE_FSLI | SBK_IMAGE_STATE_IMGI)

#define SBK_IMAGE_STATE_SSLOK                                                   \
	(SBK_IMAGE_STATE_IINF | SBK_IMAGE_STATE_PDEP | SBK_IMAGE_STATE_IDEP |   \
	 SBK_IMAGE_STATE_SSLI | SBK_IMAGE_STATE_IMGI)

#define SBK_IMAGE_STATE_SSL_DU_OK                                               \
	(SBK_IMAGE_STATE_IINF | SBK_IMAGE_STATE_PDEP | SBK_IMAGE_STATE_IDEP |   \
	 SBK_IMAGE_STATE_SSLI)

#define SBK_IMAGE_STATE_SET(state, flag)   ((state) |= (flag))
#define SBK_IMAGE_STATE_CLR(state, flag)   ((state) &= ~(flag))
#define SBK_IMAGE_STATE_ISSET(state, flag) (((state) & (flag)) == flag)

struct sbk_image_state_info {
	uint32_t state;
	uint32_t image_start_address;
	uint32_t image_sequence_number;
};

struct sbk_slot;

/**
 * @brief Enumerate swap modes
 *
 */
enum sbk_image_swap_modes {
	SBK_IMAGE_SWAP_MODE_NONE = 0,		/* No swap needed */
	SBK_IMAGE_SWAP_MODE_UPDATE = 1,		/* Update image */
	SBK_IMAGE_SWAP_MODE_RESTORE = 2,	/* Restore backup */
	SBK_IMAGE_SWAP_MODE_SWAP = 3,		/* Swap image using backup */
};

struct sbk_image_swap_state {
	struct sbk_slot *img;
	struct sbk_slot *upd;
	struct sbk_slot *bck;
	enum sbk_image_swap_modes mode;
	size_t block_size;
	uint32_t offset;
	bool bck_done;
};

/**
 * @brief sbk_image_fsl_state
 *
 * Retrieve the first stage loader state of an image in a slot
 *
 * @param slot: the slot to evaluate
 * @param st: image state
 */
void sbk_image_fsl_state(const struct sbk_slot *slot,
			 struct sbk_image_state_info *state_info);

void sbk_image_ssl_state(const struct sbk_slot *slot,
			  struct sbk_image_state_info *state_info);

bool sbk_image_ssl_swap(uint32_t idx);

int sbk_image_read(const struct sbk_slot *slot, uint32_t off, void *data,
		   size_t len);

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
