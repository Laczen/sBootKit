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

#define SBK_IMAGE_START_TAG 0x8000
#define SBK_IMAGE_SEAL_TAG 0x7FFF

struct sbk_version;
struct sbk_version_range;

struct __attribute__((packed)) sbk_image_meta_rec_hdr {
        uint16_t tag; /* odd-parity tag */
        uint16_t len; /* record length */
};

struct __attribute__((packed)) sbk_image_meta_start {
        struct sbk_image_meta_rec_hdr rec_hdr; /* image start tag = 0x8000 */
        struct sbk_version image_version;
        uint16_t image_dep_tag; /* first tag describing image dependency */
        uint16_t board_dep_tag; /* first tag describing board dependency */
        uint16_t image_state_tag; /* first tag describing image state */
        uint16_t next_tag; /* set this to 0x7FFF */
};

struct __attribute__((packed)) sbk_image_dep_info {
        struct sbk_image_meta_rec_hdr rec_hdr;
        struct sbk_version_range vrange;
        uint16_t run_slot;
        uint16_t next_tag;
};

struct __attribute__((packed)) sbk_board_dep_info {
        struct sbk_image_meta_rec_hdr rec_hdr;
        uint32_t board_id;
        struct sbk_version_range vrange;
        uint16_t next_tag;
        uint16_t pad16;
};

struct __attribute__((packed)) sbk_image_state {
        struct sbk_image_meta_rec_hdr rec_hdr;
        uint16_t slot;
        uint16_t offset;
        uint32_t size;
        uint16_t hash_tag;
        uint16_t transform_tag;
        uint16_t next_tag;
        uint16_t pad16;
};

struct sbk_os_slot;

/**
 * @brief sbk_image_board_verify
 *
 * Verifies that a image can run on the present board
 *
 * @param slot: slot that contains the image
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_board_verify(const struct sbk_os_slot *slot);

/**
 * @brief sbk_image_dependency_verify
 *
 * Verifies that all image dependencies are satisfied
 *
 * @param slot: slot that contains the image
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_dependency_verify(const struct sbk_os_slot *slot);

/**
 * @brief sbk_image_pkey_compare
 *
 * Compares the public key used in the seal to a provided public key
 *
 * @param slot: slot to read the seal from
 * @param pkey: comparison key
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_pkey_compare(const struct sbk_os_slot *slot, uint8_t *pkey);

/**
 * @brief sbk_image_get_state
 *
 * Get image state information
 *
 * @param slot: slot to read the image state from
 * @param cnt: state transformation count: an image can be in different states
 *             while being moved to its final executable state. This is linked
 *             to the slot it resides is. A image will be executable when it
 *             is in state transformation count 0, encrypted/zipped/... in a
 *             state with state transformation count > 0.
 * @param state: image state information
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_get_state(const struct sbk_os_slot *slot, uint32_t cnt,
                        struct sbk_image_state *state);
/**
 * @brief sbk_image_seal_verify
 *
 * Verify the seal of an image
 *
 * @param slot: slot where the image is located
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 *
 */
int sbk_image_seal_verify(const struct sbk_os_slot *slot);

/**
 * @brief sbk_image_hash_verify
 *
 * Verify the hash of an image
 *
 * @param slot: slot where the image is located
 * @param read_cb: read callback function
 * @param read_cb_ctx: read callback context
 * @param cnt: image state count
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 *
 */
int sbk_image_hash_verify(const struct sbk_os_slot *slot,
                          int (*read_cb)(const void *ctx, uint32_t offset,
                                         void *data, uint32_t len),
                          const void *read_cb_ctx, uint32_t cnt);

/**
 * @brief sbk_image_get_tag_data
 *
 * Search for a tag and read the tag data
 *
 * @param slot: slot where the image is located
 * @param tag: the tag to find
 * @param data: tag data
 * @param size: tag data size (correct size must be provided)
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_image_get_tag_data(const struct sbk_os_slot *slot, uint16_t tag,
                           void *data, uint32_t size);
/**
 * @brief sbk_image_bootable
 *
 * Check if image in slot is bootable
 *
 * @param slot_no: the slot to check,
 * @param address: returns the start address if the image is bootable
 */
int sbk_image_bootable(uint16_t slot_no, uint32_t *address);


#ifdef __cplusplus
}
#endif

#endif /* SBK_IMAGE_H_*/