/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SBK_PRODUCT_H_
#define SBK_PRODUCT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

struct __attribute__((packed)) sbk_version {
        uint8_t major;
        uint8_t minor;
        uint16_t revision;
};

struct __attribute__((packed)) sbk_version_range {
        struct sbk_version min_version;
        struct sbk_version max_version;
};

/**
 * @brief sbk_version_in_range
 *
 * Checks if version is inside specified range
 *
 * @param ver: version
 * @param range: range
 * @retval true if version is in range, false otherwise
 */
bool sbk_version_in_range(const struct sbk_version *ver,
                          const struct sbk_version_range *range);

/**
 * @brief sbk_product_get_hash
 *
 * Get the product hash
 */
const uint32_t *sbk_product_get_hash(void);

/**
 * @brief sbk_product_get_version
 *
 * Get the product version
 */
const struct sbk_version *sbk_product_get_version(void);

/**
 * @brief sbk_product_hash_match
 *
 * Check if product_hash matched supplied hash
 *
 * @param hash: hash to check
 * @retval: true if product hash matches hash, false otherwise
 */
bool sbk_product_hash_match(const uint32_t *hash);

/**
 * @brief sbk_product_version_in_range
 *
 * Check if product version is inside supplied range
 *
 * @param range: range to check
 * @retval: true if product version is inside range, false otherwise
 */
bool sbk_product_version_in_range(const struct sbk_version_range *range);

/**
 * @brief sbk_product_init_hash
 *
 * set the product hash pointer
 */
void sbk_product_init_hash(const uint32_t *hash);

/**
 * @brief sbk_product_init_version
 *
 * Set the product version
 */
void sbk_product_init_version(const struct sbk_version *board_version);

#ifdef __cplusplus
}
#endif

#endif /* SBK_BOARD_H_*/