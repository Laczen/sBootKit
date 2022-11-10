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

uint8_t buffer[1024];

static int read(const void *ctx, uint32_t off, void *data, uint32_t len)
{
        memcpy(data, (void *)&buffer[off], len);
        return 0;
}

static int prog(const void *ctx, uint32_t off, const void *data, uint32_t len)
{
        const uint8_t *data8 = (uint8_t *)data;

        memcpy(&buffer[off], data8, len);
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

static int slot_init(struct sbk_os_slot *slot, uint32_t slot_no)
{
        slot->ctx = NULL;
        slot->read = read;
        slot->prog = prog;
        slot->sync = sync;
        slot->get_size = get_size;
        return 0;
}

uint32_t get_slot_cnt(void)
{
        return 1U;
}

static void jump_image(uint32_t address)
{
        printk("Booted image at %d\n", address);
}

int (*sbk_os_slot_init)(struct sbk_os_slot *slot, uint32_t slot_no) = slot_init;