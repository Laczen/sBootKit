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
#define SBK_IMAGE_FLAG_CONFIRMED        0x0001
#define SBK_IMAGE_FLAG_ENCRYPTED        0x0010
#define SBK_IMAGE_FLAG_ZLIB             0x0020
#define SBK_IMAGE_FLAG_VCDIFF           0x0040
#define SBK_IMAGE_AUTH_CONTEXT  "SBK AUTHENTICATE"
#define SBK_IMAGE_ENCR_CONTEXT  "SBK ENCRYPT"

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
        uint32_t image_start_address;
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
 * @brief sbk_image_dependency_verify
 *
 * Verifies that an image in a slot can run on the present product and that all
 * image dependencies are satisfied.
 *
 * @param slot: pointer to slot where the image resides
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_dependency_verify(const struct sbk_slot *slot);

/**
 * @brief sbk_image_bootable
 *
 * Check if an image in a slot is bootable, this uses the key that is defined by
 * the first stage loader (fsl). So this should only be used from a context that
 * knows the fsl key (e.g when running as fsl).
 *
 * @param slot: pointer to slot where the image resides
 * @param address: is updated with the jump address if the image is bootable
 * @param bcnt: bootcount is reset to zero when image is confirmed
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_bootable(const struct sbk_slot *slot, unsigned long *address,
                       uint8_t *bcnt);

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
 * @brief sbk_image_valid
 *
 * Verifies the validity of an image in a slot
 *
 * @param slot: pointer to slot where the image resides
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_valid(const struct sbk_slot *slot);

#ifdef __cplusplus
}
#endif

#endif /* SBK_IMAGE_H_*/