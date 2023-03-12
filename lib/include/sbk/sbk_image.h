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

#define SBK_IMAGE_AUTH_TAG              0x7FFF
#define SBK_IMAGE_META_TAG              0x8000
#define SBK_IMAGE_FLAG_CONFIRMED        0x0001
#define SBK_IMAGE_FLAG_ENCRYPTED        0x0010
#define SBK_IMAGE_FLAG_ZLIB             0x0020
#define SBK_IMAGE_FLAG_VCDIFF           0x0040
#define SBK_IMAGE_AUTH_CONTEXT  "SBK AUTHENTICATE"
#define SBK_IMAGE_ENCR_CONTEXT  "SBK ENCRYPT"

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

struct sbk_image_buffer {
        uint8_t *buf;           /* pointer to buffer */
        size_t blen;            /* buffer size */
        uint32_t bpos;          /* buffer position */
};

struct sbk_image {
        struct sbk_os_slot *slot;      /* image slot pointer */
        struct sbk_image_buffer *ib;   /* pointer to image buffer */
};

int sbk_image_read(const struct sbk_image *image, unsigned long offset,
                   void *data, size_t len);

int sbk_image_write(const struct sbk_image *image, unsigned long offset,
                    const void *data, size_t len);

int sbk_image_flush(const struct sbk_image *image);

/**
 * @brief sbk_dependency_verify
 *
 * Verifies that a image can run on the present product and that all
 * image dependencies are satisfied.
 *
 * @param image: pointer to image struct
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_dependency_verify(const struct sbk_image *image);

/**
 * @brief sbk_image_bootable
 *
 * Check if image is bootable
 *
 * @param image: pointer to image struct
 * @param address: is updated with the jump address if the image is bootable
 * @param bcnt: bootcount is reset to zero when image is confirmed
 */
int sbk_image_bootable(const struct sbk_image *image, unsigned long *address,
                       uint8_t *bcnt);

/**
 * @brief sbk_image_get_version
 *
 * Get the version of an image
 *
 * @param image: pointer to image struct
 * @param version: returns the version as sbk_version
 */
int sbk_image_get_version(const struct sbk_image *image,
                          struct sbk_version *version);

#ifdef __cplusplus
}
#endif

#endif /* SBK_IMAGE_H_*/