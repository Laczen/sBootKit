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
#include "sbk/sbk_product.h"
#include "sbk/sbk_image.h"

#define FLASH_OFFSET CONFIG_FLASH_BASE_ADDRESS

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

/**
 * @brief shared data format definition
 */

struct sbk_shared_data {
        uint32_t product_hash;
        struct sbk_version product_ver;
        uint8_t bslot;
        uint8_t bcnt;
};

struct flash_slot_ctx {
        const struct device *dev;
        uint32_t off;
        uint32_t size;
};

const struct flash_slot_ctx slots[2] = {
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

static int read(const void *ctx, unsigned long off, void *data, size_t len)
{
        const struct flash_slot_ctx *sctx = (const struct flash_slot_ctx *)ctx;

        return flash_read(sctx->dev, sctx->off + off, data, len);
}

static int prog(const void *ctx, unsigned long off, const void *data, size_t len)
{
        const struct flash_slot_ctx *sctx = (const struct flash_slot_ctx *)ctx;
        int rc;

        if (off == 0U) {
                rc = 0;//flash_erase(sctx->dev, sctx->off + off, 131072);
                //SBK_LOG_DBG("Erased sector at %lx [%d]", sctx->off + off, rc);
                if (rc != 0) {
                        goto end;
                }
        }

        rc = flash_write(sctx->dev, sctx->off + off, data, len);
        //SBK_LOG_DBG("Written %d bytes to %lx [%d]", len, sctx->off + off, rc);
end:
        return rc;
}

static int sync(const void *ctx)
{
        return 0;
}

static unsigned long get_start_address(const void *ctx)
{
        const struct flash_slot_ctx *sctx = (const struct flash_slot_ctx *)ctx;

        return FLASH_OFFSET + sctx->off;
}

static size_t get_size(const void *ctx)
{
        const struct flash_slot_ctx *sctx = (const struct flash_slot_ctx *)ctx;

        return sctx->size;
}

static int slot_init(struct sbk_os_slot *slot, unsigned int slot_no)
{
        if (slot_no >= ARRAY_SIZE(slots)) {
                return -SBK_EC_ENOENT;
        }

        slot->ctx = (void *)&slots[slot_no];
        slot->read = read;
        slot->prog = prog;
        slot->sync = sync;
        slot->get_start_address = get_start_address;
        slot->get_size = get_size;
        return 0;
}

int (*sbk_os_slot_init)(struct sbk_os_slot *slot, unsigned int slot_no) = slot_init;
struct sbk_shared_data shared_data Z_GENERIC_SECTION(BL_SHARED_SRAM);

void main(void)
{
        SBK_LOG_INF("Welcome to %x version %d.%d-%d", shared_data.product_hash,
                shared_data.product_ver.major, 
                shared_data.product_ver.minor,
                shared_data.product_ver.revision);
        SBK_LOG_INF("Running from slot %d", shared_data.bslot);
        SBK_LOG_INF("Boot retries %d", shared_data.bcnt);
}