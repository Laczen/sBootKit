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

struct __attribute__((packed)) sbk_version {
        uint8_t major;
        uint8_t minor;
        uint16_t revision;
};

struct __attribute__((packed)) sbk_version_range {
        struct sbk_version min_version;
        struct sbk_version max_version;
};

struct __attribute__((packed)) sbk_image_dep_info {
        uint32_t slot;
        struct sbk_version_range vrange;
};

struct __attribute__((packed)) sbk_device_dep_info {
        uint8_t dev_uuid[SBK_DEVICE_UUID_SIZE];
        struct sbk_version_range vrange;
};

/**
 * @brief sbk_version_u32
 *
 * Convert version structure to uint32_t
 *
 * @param ver: version as version structure
 * @retval version
 */
uint32_t sbk_version_u32(const struct sbk_version *ver);



struct sbk_os_slot;

/**
 * @brief sbk_image_seal_verify
 */
int sbk_image_seal_verify(const struct sbk_os_slot *slot);

/**
 * @brief sbk_image_hash_verify
 */
int sbk_image_hash_verify(const struct sbk_os_slot *slot);

/**
 * @brief sbk_image_hash_verify
 */
int sbk_image_encrypted_hash_verify(const struct sbk_os_slot *slot);

/**
 * @brief sbk_image_bootable
 *
 * Check if image in slot is bootable
 */
int sbk_image_bootable(const struct sbk_os_slot *slot, uint32_t *address);

#ifdef __cplusplus
}
#endif

#endif /* SBK_IMAGE_H_*/