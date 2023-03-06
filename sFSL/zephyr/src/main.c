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

#ifndef CONFIG_PRODUCT_NAME
#define CONFIG_PRODUCT_NAME "TEST"
#endif
#ifndef CONFIG_PRODUCT_VER_MAJ
#define CONFIG_PRODUCT_VER_MAJ 0
#endif
#ifndef CONFIG_PRODUCT_VER_MIN
#define CONFIG_PRODUCT_VER_MIN 0
#endif
#ifndef CONFIG_PRODUCT_VER_REV
#define CONFIG_PRODUCT_VER_REV 0
#endif

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

#define BOOT_RETRIES 4

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
        /* The secure First Stage Loader does not program */
        return 0;
}

static int sync(const void *ctx)
{
        /* The secure First Stage Loader does not program */
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
        slot->ctx = (void *)&slots[slot_no];
        slot->read = read;
        slot->prog = prog;
        slot->sync = sync;
        slot->get_start_address = get_start_address;
        slot->get_size = get_size;
        return 0;
}

int (*sbk_os_slot_init)(struct sbk_os_slot *slot, unsigned int slot_no) = slot_init;
extern void jump_image(unsigned long address);
struct sbk_shared_data shared_data Z_GENERIC_SECTION(BL_SHARED_SRAM);

void main(void)
{
        uint32_t product_hash;

        SBK_LOG_DBG("Welcome...");
        product_hash = sbk_product_djb2_hash(CONFIG_PRODUCT_NAME,
                                             sizeof(CONFIG_PRODUCT_NAME));

        if ((shared_data.product_hash != product_hash) ||
            (shared_data.bcnt > BOOT_RETRIES) ||
            (shared_data.bslot >= ARRAY_SIZE(slots))) {
                shared_data.product_hash = product_hash;
                shared_data.product_ver.major = CONFIG_PRODUCT_VER_MAJ;
                shared_data.product_ver.minor = CONFIG_PRODUCT_VER_MIN;
                shared_data.product_ver.revision = CONFIG_PRODUCT_VER_REV;
                shared_data.bslot = 0U;
                shared_data.bcnt = 0U;
        }

        sbk_product_init_hash(&shared_data.product_hash);
        sbk_product_init_version(&shared_data.product_ver);

        if (shared_data.bcnt == BOOT_RETRIES) {
                shared_data.bslot++;
                shared_data.bcnt = 0U;
        }

        unsigned long address;
        int rc;

        for (uint32_t i = 0; i < ARRAY_SIZE(slots); i++) {
                struct sbk_os_slot slot;

                if (shared_data.bslot >= ARRAY_SIZE(slots)) {
                        shared_data.bslot = 0U;
                }

                SBK_LOG_DBG("Testing slot %d", shared_data.bslot);

                rc = sbk_os_slot_open(&slot, shared_data.bslot);
                if (rc != 0) {
                        shared_data.bslot = 0U;
                        continue;
                }

                shared_data.bcnt++;
                rc = sbk_image_bootable(&slot, &address, &shared_data.bcnt);
                (void)sbk_os_slot_close(&slot);

                if (rc != 0) {
                        SBK_LOG_DBG("Failed booting image in slot %d",
                                    shared_data.bslot);

                        shared_data.bslot++;
                        shared_data.bcnt = 0U;
                        continue;
                }

                jump_image(address);
        }

        SBK_LOG_DBG("No bootable image found");

        while(1);
}