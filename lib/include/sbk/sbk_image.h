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
#include <stdbool.h>

#include "sbk/sbk_product.h"

#define SBK_IMAGE_WBS   64
#define SBK_IMAGE_AUTH_TAG              0x7FFF
#define SBK_IMAGE_META_TAG              0x8000
#define SBK_IMAGE_FLAG_CONFIRMED        0x0001 /* Confirmed image */
#define SBK_IMAGE_FLAG_DOWNGRADE        0x0002 /* Downgrade allowed (revert) */
#define SBK_IMAGE_FLAG_ENCRYPTED        0x0010 /* Encrypted image */
#define SBK_IMAGE_FLAG_ZLIB             0x0020 /* ZLIB compressed image */
#define SBK_IMAGE_FLAG_VCDIFF           0x0040 /* VCDIFF image */
#define SBK_IMAGE_AUTH_CONTEXT  "SBK AUTHENTICATE"
#define SBK_IMAGE_ENCR_CONTEXT  "SBK ENCRYPT"
#define SBK_IMAGE_STATE_BDST            0x0001
#define SBK_IMAGE_STATE_AUTH            0x0002
#define SBK_IMAGE_STATE_IDEP            0x0004
#define SBK_IMAGE_STATE_PDEP            0x0008
#define SBK_IMAGE_STATE_CONF            0x0010
#define SBK_IMAGE_STATE_DOWN            0x0020


struct sbk_slot;

struct __attribute__((packed)) sbk_image_rec_hdr {
        uint16_t tag; /* odd-parity tag */
        uint16_t len; /* record length */
};

struct __attribute__((packed)) sbk_image_auth {
        struct sbk_image_rec_hdr rhdr;  /* record tag + length */
        uint8_t fsl_fhmac[32];          /* first stage loader hmac */
        uint8_t upd_shmac[32];          /* updater short hmac (header) */
        uint8_t upd_fhmac[32];          /* updater full hmac (header + image) */
};

struct __attribute__((packed)) sbk_image_meta {
        struct sbk_image_rec_hdr rhdr;  /* record tag + length */
        struct sbk_version image_version;
        unsigned long image_start_address;
        uint32_t image_flags;           /* flags descr. image properties */
        uint32_t image_size;            /* image size without header */
        uint16_t image_offset;          /* image offset from start of header */
        uint16_t image_dep_tag;         /* first tag descr. image dependencies */
        uint16_t product_dep_tag;       /* first tag descr. product dependency */
        uint16_t other_tag;             /* first tag describing other data */
        uint8_t salt[16];               /* salt used for key derivation */
};

struct __attribute__((packed)) sbk_image_dep_info {
        struct sbk_image_rec_hdr rhdr;  /* record tag + length */
        struct sbk_version_range vrange;
        uint32_t image_start_address; /* where is the dependent image located */
        uint16_t next_tag;
        uint16_t pad16;
};

struct __attribute__((packed)) sbk_product_dep_info {
        struct sbk_image_rec_hdr rhdr; /* record tag + length */
        struct sbk_version_range vrange;
        uint32_t product_hash;
        uint16_t next_tag;
        uint16_t pad16;
};

struct sbk_image_state {
        uint32_t state_flags;
        unsigned long image_start_address;
        size_t length;
        struct sbk_version image_version;
};

#define SBK_IMAGE_STATE_BDST_SET(flags) (flags |= SBK_IMAGE_STATE_BDST)
#define SBK_IMAGE_STATE_AUTH_SET(flags) (flags |= SBK_IMAGE_STATE_AUTH)
#define SBK_IMAGE_STATE_IDEP_SET(flags) (flags |= SBK_IMAGE_STATE_IDEP)
#define SBK_IMAGE_STATE_PDEP_SET(flags) (flags |= SBK_IMAGE_STATE_PDEP)
#define SBK_IMAGE_STATE_CONF_SET(flags) (flags |= SBK_IMAGE_STATE_CONF)
#define SBK_IMAGE_STATE_COND_IS_SET(flags, CONDITION)                           \
        (((flags) & (CONDITION)) == (CONDITION))
#define SBK_IMAGE_STATE_BDST_IS_SET(flags)                                      \
        SBK_IMAGE_STATE_COND_IS_SET(flags, SBK_IMAGE_STATE_BDST)
#define SBK_IMAGE_STATE_AUTH_IS_SET(flags)                                      \
        SBK_IMAGE_STATE_COND_IS_SET(flags, SBK_IMAGE_STATE_AUTH)
#define SBK_IMAGE_STATE_IDEP_IS_SET(flags)                                      \
        SBK_IMAGE_STATE_COND_IS_SET(flags, SBK_IMAGE_STATE_IDEP)
#define SBK_IMAGE_STATE_PDEP_IS_SET(flags)                                      \
        SBK_IMAGE_STATE_COND_IS_SET(flags, SBK_IMAGE_STATE_PDEP)
#define SBK_IMAGE_STATE_CONF_IS_SET(flags)                                      \
        SBK_IMAGE_STATE_COND_IS_SET(flags, SBK_IMAGE_STATE_CONF)

#define SBK_IMAGE_STATE_CLR_FLAGS(flags) flags = 0U
#define SBK_IMAGE_STATE_CAN_UPGR(flags)                                         \
        SBK_IMAGE_STATE_COND_IS_SET(flags,                                      \
                (SBK_IMAGE_STATE_PDEP | SBK_IMAGE_STATE_IDEP |                  \
                 SBK_IMAGE_STATE_AUTH))
#define SBK_IMAGE_STATE_CAN_BOOT(flags)                                         \
        SBK_IMAGE_STATE_COND_IS_SET(flags,                                      \
                (SBK_IMAGE_STATE_PDEP | SBK_IMAGE_STATE_IDEP |                  \
                 SBK_IMAGE_STATE_AUTH | SBK_IMAGE_STATE_BDST))

/**
 * @brief sbk_image_read
 *
 * Read data from an image in a slot, this will encrypt the data when the
 * reading is done from a slot where the image can be executed from. As this
 * uses the update key it should only be used in a context where this key is
 * known (e.g. when running as updater).
 *
 * @param slot: pointer to slot where the image resides
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_read(const struct sbk_slot *slot, unsigned long offset,
                   void *data, size_t len);

/**
 * @brief sbk_image_write
 * 
 * Write data to an image in a slot, this will decrypt the data when the writing
 * is done to a slot where the image can be executed from. As this uses the
 * update key it should only be used in a context where this key is known (e.g.
 * when running as updater).
 *
 * @param slot: pointer to slot where the image resides
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_write(const struct sbk_slot *slot, unsigned long offset,
                    const void *data, size_t len);

/**
 * @brief sbk_image_get_version
 *
 * Get the version of an image in a slot
 *
 * @param slot: pointer to slot where the image resides
 * @param version: returns the version as sbk_version
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
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
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_get_length(const struct sbk_slot *slot, size_t *length);

/**
 * @brief sbk_image_get_state_fsl
 *
 * Get the image state from a first stage loader (fsl) perspective. This uses
 * the fsl key and will only provide valid authentication results when running
 * as first stage loader.
 *
 * @param slot: pointer to slot where the image resides
 * @param sbk_image_state: image state containing image info and flags
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_get_state_fsl(const struct sbk_slot *slot, 
                            struct sbk_image_state *st);

/**
 * @brief sbk_image_get_state_upd
 *
 * Get the image state from a updater (upd) perspective. This uses the upd key
 * and will only provide valid authentication results when running as updater
 *
 * @param slot: pointer to slot where the image resides
 * @param sbk_image_state: image state containing image info and flags
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_get_state_upd(const struct sbk_slot *slot, 
                            struct sbk_image_state *st);

/**
 * @brief sbk_image_get_state_hdr
 *
 * Get the image state from a updater (upd) perspective using only the image
 * header. This uses the upd key and will only provide valid authentication
 * results when running as updater
 *
 * @param slot: pointer to slot where the image resides
 * @param sbk_image_state: image state containing image info and flags
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_get_state_hdr(void *data, size_t len, struct sbk_image_state *st);

int sbk_image_copy(const struct sbk_slot *dest, const struct sbk_slot *src);

/**
 * @brief sbk_image_swap
 * 
 * Swap images from src to dest using temporary slot
 * 
 * @param dest: destination slot
 * @param src: source slot 
 * @param tmp: temporary slot 
 * @param erase_block_size 
 * @retval -ERRNO errno code if errror
 * @retval 0 if succesfull 
 */
int sbk_image_swap(const struct sbk_slot *dest, const struct sbk_slot *src,
		   const struct sbk_slot *tmp, size_t erase_block_size);

#ifdef __cplusplus
}
#endif

#endif /* SBK_IMAGE_H_*/