/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sbk/sbk_product.h"

#include <string.h>

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

static struct sbk_product *sbk_product = NULL;

void sbk_set_product(const struct sbk_product *product)
{
        sbk_product = product;
}

struct sbk_product *sbk_get_product(void)
{
        return sbk_product;
}
