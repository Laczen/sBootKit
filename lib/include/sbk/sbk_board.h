/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SBK_BOARD_H_
#define SBK_BOARD_H_

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
 * @brief sbk_get_board_id
 *
 * Get the board id
 */
const uint32_t *sbk_get_board_id(void);

/**
 * @brief sbk_get_board_version
 *
 * Get the board version
 */
const struct sbk_version *sbk_get_board_version(void);

/**
 * @brief sbk_board_id_match
 *
 * Check if board id matched supplied id
 *
 * @param id: id to check
 * @retval: true if id matches device id, false otherwise
 */
bool sbk_board_id_match(const uint32_t *id);

/**
 * @brief sbk_board_version_in_range
 *
 * Check if board version is inside supplied range
 *
 * @param range: range to check
 * @retval: true if board version is inside range, false otherwise
 */
bool sbk_board_version_in_range(const struct sbk_version_range *range);

/**
 * @brief sbk_init_board_id
 *
 * set the board id pointer
 */
void sbk_init_board_id(const uint32_t *board_id);

/**
 * @brief sbk_init_board_version
 *
 * Set the board version
 */
void sbk_init_board_version(const struct sbk_version *board_version);

#ifdef __cplusplus
}
#endif

#endif /* SBK_BOARD_H_*/