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
#include "sbk/sbk_slot.h"
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

struct __attribute__((aligned (BL_SHARED_SRAM_SIZE))) sbk_shared_data {
        uint32_t product_hash;
        struct sbk_version product_ver;
        uint8_t bslot;
        uint8_t bcnt;
};

struct sbk_shared_data shared_data Z_GENERIC_SECTION(BL_SHARED_SRAM_SECT);

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

static int address(const void *ctx, unsigned long off, unsigned long *address)
{
        const struct flash_slot_ctx *sctx = (const struct flash_slot_ctx *)ctx;

        *address = FLASH_OFFSET + sctx->off;
        return 0;
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

static int slot_get(struct sbk_slot *slot, unsigned int slot_no)
{
        if (slot_no >= ARRAY_SIZE(slots)) {
                return -SBK_EC_ENOENT;
        }

        slot->ctx = (void *)&slots[slot_no];
        slot->size = slots[slot_no].size;
        slot->read = read;
        slot->prog = prog;
        slot->address = address;
        slot->open = NULL;
        slot->close = NULL;
        return 0;
}

int (*sbk_slot_get)(struct sbk_slot *slot, unsigned int slot_no) = slot_get;


/**
 * @brief Shell interface
 * 
 */

int cli_command_reboot(const struct shell *sh, int argc, char *argv[]) {
        shell_print(sh, "Rebooting");
        return 0;
}

#define IMG_BUF_SIZE 512
static uint8_t img_buffer[IMG_BUF_SIZE];
static size_t ldsize;
static unsigned long ldoff;
static bool ldok;
static struct sbk_slot ldslot;

void cli_upload_block(const struct shell *sh, uint8_t *data, size_t len)
{
        int rc;

        while (len != 0) {
                unsigned long boff = ldoff & (IMG_BUF_SIZE - 1);
                unsigned long wroff = ldoff & ~(IMG_BUF_SIZE - 1);
                size_t cplen = SBK_MIN(len, IMG_BUF_SIZE - boff);

                memcpy(img_buffer + boff, data, cplen);
                boff += cplen;
                len -= cplen;
                ldoff += cplen;
                ldsize -= cplen;
                data += cplen;

                if (ldoff == 512) {
                        if (sbk_image_hdr_valid(img_buffer, ldoff) != 0) {
                                shell_print(sh, "bad image");
                                ldok = false;
                        }
                }

                if (((boff == IMG_BUF_SIZE) || (ldsize == 0U)) && (ldok)) {
                        rc = sbk_image_write(&ldslot, wroff, img_buffer, boff);
                        if (rc != 0) {
                                ldok = false;
                                shell_print(sh, "Write failed");
                        }
                }
        }

        if (ldsize == 0U) {
                sbk_slot_close(&ldslot);
                shell_set_bypass(sh, NULL);
                return;
        }

        if ((ldoff % 256) == 0) {
                shell_print(sh, "off: %ld, rs: %d OK", ldoff, ldsize);
        }

}

void main(void);

static bool is_running(const struct sbk_slot *slt) {
        const unsigned long ma = (unsigned long)main;
        unsigned long saddr;
        
        if ((sbk_slot_address(slt, 0U, &saddr) != 0) ||
            (saddr > ma) || ((saddr + slt->size) <= ma)) {
                return false;
        }

        return true;
}

int cli_command_upload(const struct shell *sh, int argc, char *argv[]) {
        uint32_t slot;

        if (argc < 2) {
                shell_print(sh, "Insufficient arguments");
                return 0;
        }

        slot = strtoul(argv[1], NULL, 0);
        ldsize = strtoul(argv[2], NULL, 0);

        if (sbk_slot_get(&ldslot, slot) != 0) {
                shell_print(sh, "Bad slot specified");
                return 0;
        }

        if (sbk_slot_open(&ldslot) != 0) {
                shell_print(sh, "Cannot open slot %d", slot);
                return 0;
        }

        if (ldslot.size < ldsize) {
                shell_print(sh, "Image to large");
                return 0;
        }

        if (is_running(&ldslot)) {
                shell_print(sh, "Cannot upgrade running image");
                return 0;
        }

        ldoff = 0U;
        ldok = true;

        shell_print(sh, "Writing %d bytes to slot %d ...", ldsize, slot);
        shell_print(sh, "OK");
        shell_set_bypass(sh, NULL);
        shell_set_bypass(sh, cli_upload_block);
        return 0;
}

static bool is_valid(const struct sbk_slot *slt) {
        return (sbk_image_valid(slt) == 0);
}

int cli_command_list(const struct shell *sh, int argc, char *argv[]) {
        uint32_t slot_no = 0;
        struct sbk_slot slot;
        struct sbk_version version;
	
        while (true) {
                int rc;
                
                rc = sbk_slot_get(&slot, slot_no);
                if (rc != 0) {
                        break;
                }

                rc = sbk_slot_open(&slot);
                if (rc != 0) {
                        break;
                }
                
                rc = sbk_image_get_version(&slot, &version);
                if (rc != 0) {
                        break;
                }

                shell_print(sh, "Slot %d contains version %d.%d-%d %s %s",
                            slot_no, version.major, version.minor,
                            version.revision, 
                            is_running(&slot) ? "(running)" : "",
                            is_valid(&slot) ? "(valid)" : "(invalid)");
                (void)sbk_slot_close(&slot);
                slot_no++;
        }

	return 0;

}

SHELL_STATIC_SUBCMD_SET_CREATE(
        image,
        SHELL_CMD(upload, NULL, "Upload new firmware", cli_command_upload),
        SHELL_CMD(list, NULL, "List available images", cli_command_list),
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