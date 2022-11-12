/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/linker/devicetree_regions.h>

#include "sbk/sbk_os.h"
#include "sbk/sbk_util.h"
#include "sbk/sbk_sfsl.h"
#include "sbk/sbk_image.h"

#define SLOT0_NODE		DT_NODELABEL(slot0_partition)
#define SLOT0_MTD               DT_MTD_FROM_FIXED_PARTITION(SLOT0_NODE)
#define SLOT0_DEVICE	        DEVICE_DT_GET(SLOT0_MTD)
#define SLOT0_OFFSET	        DT_REG_ADDR(SLOT0_NODE)
#define SLOT0_SIZE              DT_REG_SIZE(SLOT0_NODE)
#define SLOT1_NODE		DT_NODELABEL(slot1_partition)
#define SLOT1_MTD               DT_MTD_FROM_FIXED_PARTITION(SLOT1_NODE)
#define SLOT1_DEVICE	        DEVICE_DT_GET(SLOT1_MTD)
#define SLOT1_OFFSET	        DT_REG_ADDR(SLOT1_NODE)
#define SLOT1_SIZE              DT_REG_SIZE(SLOT1_NODE)

#define BL_SHARED_SRAM_NODE	DT_NODELABEL(bl_shared_sram)
#define BL_SHARED_SRAM_SECT	LINKER_DT_NODE_REGION_NAME(BL_SHARED_SRAM_NODE)
#define BL_SHARED_SRAM_ADDR	DT_REG_ADDR(BL_SHARED_SRAM_NODE)
#define BL_SHARED_SRAM_SIZE	DT_REG_SIZE(BL_SHARED_SRAM_NODE)

#define SBK_BOOT_RETRIES        4

/**
 * @brief shared data format definition
 */

struct sbk_shared_data {
        uint8_t dev_uuid[16];
        uint8_t bslot;
        uint8_t bcnt;
};

struct flash_slot_ctx {
        const struct device *dev;
        uint32_t off;
        uint32_t size;
};

const struct flash_slot_ctx slot_ctx[2] = {
        {
                .dev = SLOT0_DEVICE,
                .off = SLOT0_OFFSET,
                .size = SLOT0_SIZE,
        },
        {
                .dev = SLOT1_DEVICE,
                .off = SLOT1_OFFSET,
                .size = SLOT1_SIZE,
        }
};

static int read(const void *ctx, uint32_t off, void *data, uint32_t len)
{
        const struct flash_slot_ctx *sctx = (const struct flash_slot_ctx *)ctx;

        return flash_read(sctx->dev, sctx->off + off, data, len);
}

static int prog(const void *ctx, uint32_t off, const void *data, uint32_t len)
{
        /* The secure First Stage Loader does not program */
        return 0;
}

static int sync(const void *ctx)
{
        /* The secure First Stage Loader does not program */
        return 0;
}

static uint32_t get_start_address(const void *ctx)
{
        const struct flash_slot_ctx *sctx = (const struct flash_slot_ctx *)ctx;

        return sctx->off;
}

static uint32_t get_size(const void *ctx)
{
        const struct flash_slot_ctx *sctx = (const struct flash_slot_ctx *)ctx;

        return sctx->size;
}

static int slot_init(struct sbk_os_slot *slot, uint32_t slot_no)
{
        slot->ctx = (void *)&slot_ctx[slot_no];
        slot->read = read;
        slot->prog = prog;
        slot->sync = sync;
        slot->get_start_address = get_start_address;
        slot->get_size = get_size;
        return 0;
}

int (*sbk_os_slot_init)(struct sbk_os_slot *slot, uint32_t slot_no) = slot_init;
extern void jump_image(uint32_t address);
struct sbk_shared_data shared_data Z_GENERIC_SECTION(BL_SHARED_SRAM);

void main(void)
{
        SBK_DEVICE_UUID_DEFINE(0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
                               0xCC, 0xCC, 0xCC, 0xCC, 0xDD, 0xDD, 0xDD, 0xDD);
        SBK_DEVICE_VERSION_DEFINE(0,0,0);

        memcpy(&shared_data.dev_uuid, &dev_uuid, SBK_DEVICE_UUID_SIZE);

        sbk_set_device_uuid(&shared_data.dev_uuid[0]);
        sbk_set_device_version(&dev_version);

        if (shared_data.bcnt == SBK_BOOT_RETRIES) {
                shared_data.bslot++;
                shared_data.bcnt = 0U;
        }

        struct sbk_os_slot slot;
        uint32_t address;
        int rc;

        for (uint32_t i = 0; i < ARRAY_SIZE(slot_ctx); i++) {
                if (shared_data.bslot == ARRAY_SIZE(slot_ctx)) {
                        shared_data.bslot = 0U;
                }

                rc = sbk_os_slot_open(&slot, shared_data.bslot);
                if (rc != 0) {
                        shared_data.bslot++;
                        shared_data.bcnt = 0U;
                        continue;
                }

                rc = sbk_image_bootable(&slot, &address);
                if (rc == 0) {
                        jump_image(address);
                }

                (void)sbk_os_slot_close(&slot);

        }

        while(1);
}