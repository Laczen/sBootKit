/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sbk/sbk_product.h"

#include <string.h>

uint32_t *product_hash_ptr;
struct sbk_version *product_version_ptr;

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

const struct sbk_version *sbk_product_get_version(void)
{
        return product_version_ptr;
}

const uint32_t *sbk_product_get_hash(void)
{
        return product_hash_ptr;
}

bool sbk_product_hash_match(const uint32_t *hash)
{
        if (product_hash_ptr == NULL) {
                return false;
        }

        return ((*hash) == (*product_hash_ptr));
}

bool sbk_product_version_in_range(const struct sbk_version_range *range)
{
        if (product_version_ptr == NULL) {
                return false;
        }

        return sbk_version_in_range(product_version_ptr, range);
}

void sbk_product_init_hash(const uint32_t *hash)
{
        product_hash_ptr = (uint32_t *)hash;
}

void sbk_product_init_version(const struct sbk_version *dev_version)
{
        product_version_ptr = (struct sbk_version *)dev_version;
}
