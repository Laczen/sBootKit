/*
 * Copyright (c) 2022 Laczen
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <zephyr/sys/printk.h>
#include "sbk/sbk_os.h"

ZTEST_SUITE(sbk_os_tests, NULL, NULL, NULL, NULL, NULL);

/**
 * @brief Test working with slot
 */
ZTEST(sbk_os_tests, os_slot)
{
        int err;
        struct sbk_os_slot slot;
        uint8_t test_data[]="Just a test string";
        uint8_t rd_data[sizeof(test_data)];

        err = sbk_os_slot_open(&slot, 0);
        zassert_true(err == 0, "Failed slot open: [err %d]", err);

        zassert_true(slot.read != NULL, "slot read config error");
        zassert_true(slot.prog != NULL, "slot prog config error");
        zassert_true(slot.sync != NULL, "slot sync config error");

        err = sbk_os_slot_prog(&slot, 0, test_data, sizeof(test_data));
        zassert_true(err == 0, "Failed slot prog: [err %d]", err);

        err = sbk_os_slot_read(&slot, 0, rd_data, sizeof(test_data));
        zassert_true(err == 0, "Failed slot read: [err %d]", err);

        err = memcmp(test_data, rd_data, sizeof(test_data));
        zassert_true(err == 0, "Failed data compare");

        err = sbk_os_slot_close(&slot);
        zassert_true(err == 0, "Failed slot close: [err %d]", err);
}