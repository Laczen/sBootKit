/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sbk/sbk_board.h"

#include <string.h>

uint32_t *board_id_ptr;
struct sbk_version *board_version_ptr;

static uint32_t sbk_version_u32(const struct sbk_version *ver)
{
        return (uint32_t)((ver->major << 24) + (ver->minor << 16) +
                          ver->revision);
}

bool sbk_version_in_range(const struct sbk_version *ver,
                          const struct sbk_version_range *range)
{
        const struct sbk_version min = range->min_version;
        const struct sbk_version max = range->max_version;

        if (sbk_version_u32(ver) < sbk_version_u32(&min)) {
                return false;
        }

        if (sbk_version_u32(ver) > sbk_version_u32(&max)) {
                return false;
        }

        return true;
}

const struct sbk_version *sbk_get_board_version(void)
{
        return board_version_ptr;
}

const uint32_t *sbk_get_board_id(void)
{
        return board_id_ptr;
}

bool sbk_board_id_match(const uint32_t *id)
{
        if (board_id_ptr == NULL) {
                return false;
        }

        return ((*id) == (*board_id_ptr));
}

bool sbk_board_version_in_range(const struct sbk_version_range *range)
{
        if (board_version_ptr == NULL) {
                return false;
        }

        return sbk_version_in_range(board_version_ptr, range);
}

void sbk_init_board_id(const uint32_t *board_id)
{
        board_id_ptr = (uint32_t *)board_id;
}

void sbk_init_board_version(const struct sbk_version *dev_version)
{
        board_version_ptr = (struct sbk_version *)dev_version;
}
