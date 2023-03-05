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

#define SBK_IMAGE_AUTH_TAG              0x7FFF
#define SBK_IMAGE_META_TAG              0x8000
#define SBK_IMAGE_FLAG_ZLIB             0x0001
#define SBK_IMAGE_FLAG_VCDIFF           0x0002
#define SBK_IMAGE_FLAG_CONFIRMED        0x0010

#define BOOT_CTX        "sbk1.0 BOOT"
#define LOAD_CTX        "sbk1.0 LOAD"
#define AAD_CTX         "sbk1.0 AAD"

struct sbk_version;
struct sbk_version_range;

struct __attribute__((packed)) sbk_image_rec_hdr {
        uint16_t tag; /* odd-parity tag */
        uint16_t len; /* record length */
};

struct __attribute__((packed)) sbk_image_auth {
        struct sbk_image_rec_hdr rhdr;  /* record tag + length */
        uint8_t fsl_fhmac[32];          /* first stage loader hmac */
        uint8_t ldr_shmac[32];          /* loader short hmac (header) */
        uint8_t ldr_fhmac[32];          /* loader full hmac (header + image) */
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

struct sbk_os_slot;

/**
 * @brief sbk_product_dependency_verify
 *
 * Verifies that a image in a slot can run on the present product
 *
 * @param slot: slot that contains the image
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_product_dependency_verify(const struct sbk_os_slot *slot);

/**
 * @brief sbk_image_dependency_verify
 *
 * Verifies that all image dependencies are satisfied for a image in a slot
 *
 * @param slot: slot that contains the image
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_dependency_verify(const struct sbk_os_slot *slot);

/**
 * @brief sbk_image_bootable
 *
 * Check if image in slot is bootable
 *
 * @param slot: slot that contains the image
 * @param address: is updated with the jump address if the image is bootable
 */
int sbk_image_bootable(const struct sbk_os_slot *slot, unsigned long *address);

/**
 * @brief sbk_image_get_version
 *
 * Get the version of a image in a slot
 *
 * @param slot: slot that contains the image
 * @param version: returns the version as sbk_version
 */
int sbk_image_get_version(const struct sbk_os_slot *slot,
                          struct sbk_version *version);

/**
 * @brief sbk_image_swap
 *
 * swap the image from slot in to slot out using an optional intermediate slot
 *
 * @param in: slot containing the update image
 * @param out: slot containing the old image
 * @param im: intermediate slot to store the old image while doing the swap
 *            (when set to NULL the swap will perform an overwrite and the
 *             old image is lost).
 * @param version: returns the version as sbk_version
 */
int sbk_image_swap(const struct sbk_os_slot *in, const struct sbk_os_slot *out,
                   const struct sbk_os_slot *im);

#ifdef __cplusplus
}
#endif

#endif /* SBK_IMAGE_H_*/