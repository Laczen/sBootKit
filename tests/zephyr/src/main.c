/*
 * Copyright (c) 2021 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/sys/printk.h>
#include "sbk/sbk_os.h"

uint8_t buffer[2048];

static int read(const void *ctx, uint32_t off, void *data, uint32_t len)
{
        memcpy(data, (void *)&buffer[off], len);
        return 0;
}

static int prog(const void *ctx, uint32_t off, const void *data, uint32_t len)
{
        memcpy(&buffer[off], (uint8_t *)data, len);
        return 0;
}

static int sync(const void *ctx)
{
        /* flush remaining data to backend */

        /* free stores entry */
        return 0;
}

static uint32_t get_size(const void *ctx)
{
        return (uint32_t)sizeof(buffer);
}

static uint32_t get_start_address(const void *ctx)
{
        return 0U;
}

static int slot_init(struct sbk_os_slot *slot, uint32_t slot_no)
{
        slot->ctx = NULL;
        slot->read = read;
        slot->prog = prog;
        slot->sync = sync;
        slot->get_size = get_size;
        slot->get_start_address = get_start_address;
        return 0;
}

uint32_t get_slot_cnt(void)
{
        return 1U;
}

int (*sbk_os_slot_init)(struct sbk_os_slot *slot, uint32_t slot_no) = slot_init;