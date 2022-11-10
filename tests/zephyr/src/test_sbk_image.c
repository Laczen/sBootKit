/*
 * Copyright (c) 2019 Laczen
 * Copyright (c) 2017 Nordic Semiconductor ASA
 * Copyright (c) 2015 Runtime Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>

#include "sbk/sbk_image.h"
#include "sbk/sbk_os.h"

SBK_DEVICE_UUID_DEFINE(0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
                       0xCC, 0xCC, 0xCC, 0xCC, 0xDD, 0xDD, 0xDD, 0xDD);
SBK_DEVICE_VERSION_DEFINE(0,0,0);

ZTEST_SUITE(sbk_image_tests, NULL, NULL, NULL, NULL, NULL);

/**
 * @brief
 */
ZTEST(sbk_image_tests, sbk_image_bootable)
{
        struct sbk_os_slot slot;
        uint32_t boot_address;
        int err;

        err = sbk_os_slot_open(&slot, 0);
        zassert_true(err == 0, "Failed slot open: [err %d]", err);

	// err = sbk_image_bootable(&slot, &boot_address);
	// zassert_false(err == 0, "Image bootable");
}
