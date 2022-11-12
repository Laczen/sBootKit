/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sbk/sbk_sfsl.h"

#include <string.h>

uint8_t *dev_uuid_ptr;
struct sbk_version *dev_version_ptr;

uint32_t sbk_version_u32(const struct sbk_version *ver)
{
        return (uint32_t)((ver->major << 24) + (ver->minor << 16) +
                          ver->revision);
}

const struct sbk_version *sbk_get_device_version(void)
{
        return dev_version_ptr;
}

const uint8_t *sbk_get_device_uuid(void)
{
        return dev_uuid_ptr;
}

void sbk_set_device_uuid(const uint8_t *dev_uuid)
{
        dev_uuid_ptr = (uint8_t *)dev_uuid;
}

void sbk_set_device_version(const struct sbk_version *dev_version)
{
        dev_version_ptr = (struct sbk_version *)dev_version;
}
