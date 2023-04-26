/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/linker/devicetree_regions.h>
#include <zephyr/shell/shell.h>

#include "sbk/sbk_image.h"
#include "sbk/sbk_os.h"
#include "sbk/sbk_util.h"
#include "sbk/sbk_product.h"

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

/**
 * @brief Loader slot setup
 * 
 */

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

        if (((sctx->off + off) % 0x20000) == 0U) {
                rc = flash_erase(sctx->dev, sctx->off + off, 131072);
                if (rc != 0) {
                        goto end;
                }
        }

        rc = flash_write(sctx->dev, sctx->off + off, data, len);
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

/**
 * @brief Shell interface
 * 
 */

int cli_command_reboot(const struct shell *sh, int argc, char *argv[]) {
        shell_print(sh, "Rebooting");
        return 0;
}

#define IMG_BUF_SIZE 512
static size_t ldsize;
static size_t ldoffset;
static bool ldok;
static uint8_t img_buffer[IMG_BUF_SIZE];
static struct sbk_os_slot ldslot;
static struct sbk_image_buffer ldimage_buf = {
        .buf = img_buffer,
        .blen = IMG_BUF_SIZE,
};
static struct sbk_image ldimage = {
        .slot = &ldslot,
        .ib = &ldimage_buf,
};

void cli_load(const struct shell *sh, uint8_t *data, size_t len)
{
        if (ldok) {
                if (sbk_image_write(&ldimage, ldoffset, data, len) != 0) {
                        shell_print(sh, "Write failed");
                        ldok = false;
                }
        }

        ldsize -= len;
        ldoffset += len;

        if (ldsize == 0U) {
                if ((ldok) && (sbk_image_flush(&ldimage) == 0)) {
                        shell_print(sh, "Write done");

                } else {
                        shell_print(sh, "Write error");
                }

                shell_set_bypass(sh, NULL);
                return;
        }

        if ((ldoffset % 256) == 0) {
                shell_print(sh, "off: %ld, rs: %d OK",
                            ldimage_buf.bstart + ldimage_buf.bpos, ldsize);
        }
}

void main(void);

int cli_command_load(const struct shell *sh, int argc, char *argv[]) {
        uint32_t slot;

        if (argc < 2) {
                shell_print(sh, "Insufficient arguments");
                return 0;
        }

        slot = strtoul(argv[1], NULL, 0);
        ldsize = strtoul(argv[2], NULL, 0);

        if (sbk_os_slot_open(&ldslot, slot) != 0) {
                shell_print(sh, "Bad slot specified");
                return 0;
        }

        if (sbk_os_slot_get_sz(&ldslot) < ldsize) {
                shell_print(sh, "Image to large");
                return 0;
        }

        if (sbk_os_slot_inrange(&ldslot, (unsigned long)main)) {
                shell_print(sh, "Cannot upgrade running image");
                return 0;
        }

        ldoffset = 0U;
        ldimage_buf.bstart = 0U;
        ldimage_buf.bpos = 0U;
        ldok = true;

        shell_print(sh, "Writing %d bytes to slot %d ...", ldsize, slot);
        shell_print(sh, "OK");
        shell_set_bypass(sh, NULL);
        shell_set_bypass(sh, cli_load);
        return 0;
}

int cli_command_ilist(const struct shell *sh, int argc, char *argv[]) {
        uint32_t slot_no = 0;
        struct sbk_os_slot slot;
        struct sbk_image image = {
                .slot = &slot,
        };
        struct sbk_version version;
	
        while (true) {
                int rc;
                bool running;

                rc = sbk_os_slot_open(image.slot, slot_no);
                if (rc != 0) {
                        break;
                }
                
                rc = sbk_image_get_version(&image, &version);
                if (rc != 0) {
                        break;
                }

                running = sbk_os_slot_inrange(image.slot, (unsigned long)main);
                shell_print(sh, "Slot %d contains version %d.%d-%d %s", slot_no,
                            version.major, version.minor, version.revision,
                            running ? "(running)" : "");
                slot_no++;
        }

	return 0;

}

SHELL_STATIC_SUBCMD_SET_CREATE(
        image,
        SHELL_CMD(load, NULL, "Upload new firmware", cli_command_load),
        SHELL_CMD(list, NULL, "List available images", cli_command_ilist),
        SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(image, &image, "Working with images", NULL);

void main(void)
{          
        SBK_LOG_INF("Welcome to %x version %d.%d-%d", shared_data.product_hash,
                shared_data.product_ver.major, 
                shared_data.product_ver.minor,
                shared_data.product_ver.revision);
        SBK_LOG_INF("Running from slot %d", shared_data.bslot);
        SBK_LOG_INF("Boot retries %d", shared_data.bcnt);
        SBK_LOG_INF("Main located at: %p", main);
}