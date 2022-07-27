/*
 * Copyright (c) 2021 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <zephyr.h>
#include <ztest.h>
#include <sys/printk.h>
#include "sbk/sbk_os.h"
#include "sbk/sbk_util.h"
#include "sbk/sbk_boot.h"

struct slot {
        struct sbk_os_slot os_slot;
        uint32_t slot_no;
        bool in_use;
};

static struct slot slots[4];
const uint32_t slot_cnt = sizeof(slots)/sizeof(slots[0]);

uint8_t buffer[1024];

static int read(const struct sbk_os_slot *slot, uint32_t off, void *data, 
                uint32_t len)
{
        if ((off + len) >= (slot->ebsize * slot->ebcnt)) {
                return -SBK_EC_EIO;
        }

        memcpy(data, (void *)&buffer[off], len);
        return 0;
}

static int prog(const struct sbk_os_slot *slot, uint32_t off,
                const void *data, uint32_t len)
{
        const uint8_t *data8 = (uint8_t *)data;

        if ((off + len) >= (slot->ebsize * slot->ebcnt)) {
                return -SBK_EC_EIO;
        }

        memcpy(&buffer[off], data8, len);
        return 0;
}

static int close(const struct sbk_os_slot *slot)
{
        /* flush remaining data to backend */
        
        /* free stores entry */
        return 0;
}

struct sbk_os_slot* get_slot(uint32_t slot_no)
{
        uint32_t slot_idx = 0;

        while (1) {
                if (slot_idx == slot_cnt) {
                        return NULL;
                }

                if (!slots[slot_idx].in_use) {
                        break;
                }
                slot_idx++;
        }

        slots[slot_idx].in_use = true;
        slots[slot_idx].slot_no = slot_no;
        slots[slot_idx].os_slot.ebsize = 256;
        slots[slot_idx].os_slot.ebcnt = 4;
        slots[slot_idx].os_slot.rread = read;
        slots[slot_idx].os_slot.uread = read;
        slots[slot_idx].os_slot.rprog = prog;
        slots[slot_idx].os_slot.uprog = prog;
        slots[slot_idx].os_slot.close = close;
                
        return &slots[slot_idx].os_slot;
}

uint32_t get_slot_cnt(void)
{
        return 1U;
}

struct sbk_os_slot* (*sbk_os_get_slot)(uint32_t slot_no) = get_slot;
uint32_t (*sbk_os_get_slot_cnt)(void) = get_slot_cnt;

static void jump_image(uint32_t slot_no)
{
        printk("Booted image in slot %d\n", slot_no);
}
const void (*sbk_os_jump_image)(uint32_t slot_no) = jump_image;

/* Disable Logger */
const void (*sbk_os_log)(int level, const char *fmt, ...) = NULL;

extern void test_sbk_os(void);
extern void test_sbk_tlv(void);
extern void test_sbk_crypto(void);

void test_main(void)
{
        test_sbk_os();
        test_sbk_tlv();
        test_sbk_crypto();
        (void)sbk_boot();

}