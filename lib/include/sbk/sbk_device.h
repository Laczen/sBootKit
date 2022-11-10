/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SBK_DEVICE_H_
#define SBK_DEVICE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define SBK_DEVICE_UUID_SIZE 16
#define SBK_DEVICE_UUID_DEFINE(_u0, _u1, _u2, _u3, _u4, _u5, _u6, _u7, _u8,    \
                               _u9, _u10, _u11, _u12, _u13, _u14, _u15)        \
	const uint8_t dev_uuid[SBK_DEVICE_UUID_SIZE] = {                       \
                _u0, _u1, _u2, _u3, _u4, _u5, _u6, _u7, _u8, _u9, _u10, _u11,  \
                _u12, _u13, _u14, _u15                                         \
        }

#define SBK_DEVICE_VERSION_DEFINE(_major, _minor, _revision)                   \
        const struct sbk_version dev_version = {                               \
                .major = _major,                                               \
                .minor = _minor,                                               \
                .revision = _revision,                                         \
        }

/**
 * @brief sbk_device_uuid_init
 *
 * Initialize the device by settings the device id.
 */
void sbk_device_uuid_init(void);

/**
 * @brief sbk_get_device_uuid
 *
 * Get the device id as uuid (16 byte)
 */
const uint8_t *sbk_get_device_uuid(void);

/**
 * @brief sbk_get_device_version
 *
 * Get the device version
 */
const struct sbk_version *sbk_get_device_version(void);

#ifdef __cplusplus
}
#endif

#endif /* SBK_IMAGE_META_H_*/