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
#include <stddef.h>
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

struct sbk_product {
	char *name;
	size_t name_size;
        struct sbk_version *version;
};

void sbk_set_product(const struct sbk_product *product);

struct sbk_product *sbk_get_product(void);

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


#ifdef __cplusplus
}
#endif

#endif /* SBK_BOARD_H_*/