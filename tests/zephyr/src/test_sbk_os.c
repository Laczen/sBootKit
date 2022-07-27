/*
 * Copyright (c) 2022 Laczen
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ztest.h>
#include <sys/printk.h>
#include "sbk/sbk_os.h"

/**
 * @brief Test working with slot
 */
void test_sbk_os_slot(void)
{
        int err;
        struct sbk_os_slot *slot = sbk_os_get_slot(0);
        uint8_t test_data[]="Just a test string";
        uint8_t rd_data[sizeof(test_data)];

        zassert_true(slot != NULL, "Failed to get slot from os: [err %d]");
        zassert_true(slot->rread != NULL, "slot rread config error");
        zassert_true(slot->uread != NULL, "slot uread config error");
        zassert_true(slot->rprog != NULL, "slot rprog config error");
        zassert_true(slot->uprog != NULL, "slot uprog config error");
        zassert_true(slot->close != NULL, "slot close config error");

        err = sbk_os_slot_rprog(slot, 0, test_data, sizeof(test_data));
        zassert_true(err == 0, "Failed slot rprog: [err %d]", err);

        err = sbk_os_slot_rread(slot, 0, rd_data, sizeof(test_data));
        zassert_true(err == 0, "Failed slot rread: [err %d]", err);

        err = memcmp(test_data, rd_data, sizeof(test_data));
        zassert_true(err == 0, "Failed data compare");

        err = sbk_os_slot_close(slot);
        zassert_true(err == 0, "Failed slot close");
}

void test_sbk_os(void)
{
	ztest_test_suite(test_sbk_os,
			 ztest_unit_test(test_sbk_os_slot)
	);

	ztest_run_test_suite(test_sbk_os);
}