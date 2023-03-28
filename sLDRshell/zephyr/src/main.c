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

#include "sbk/sbk_image.h"
#include "sbk/sbk_os.h"
#include "sbk/sbk_util.h"
#include "sbk/sbk_product.h"

#include "tshell.h"
#include "uart_handle.h"

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

        if ((off % 0x20000) == 0U) {
                rc = 0;//flash_erase(sctx->dev, sctx->off + off, 131072);
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

/**
 * @brief Shell interface
 * 
 */

int cli_command_reboot(const struct tshell *tsh, int argc, char *argv[]) {
        tshell_put(tsh, "Rebooting");
        return 0;
}

static size_t ldsize;
static size_t ldslot;
// #define IMG_BUF_SIZE 512
// static struct k_mutex load_lock;
// static uint32_t load_total;
// static uint32_t load_written;
// static uint8_t img_buffer[IMG_BUF_SIZE];
// static struct sbk_os_slot load_slot;
// static struct sbk_image_buffer load_image_buf = {
//         .buf = img_buffer,
//         .blen = IMG_BUF_SIZE,
// };
// static struct sbk_image load_image = {
//         .slot = &load_slot,
//         .ib = &load_image_buf,
// };
// static bool load_ok;

// static int set_bypass(const struct shell *sh, shell_bypass_cb_t bypass)
// {
// 	static bool in_use;

// 	if (bypass && in_use) {
// 		shell_error(sh, "load supports setting bypass on a single instance.");

// 		return -EBUSY;
// 	}

// 	/* Mark that we have set or unset the bypass function */
// 	in_use = bypass != NULL;

// 	if (in_use) {
// 		shell_print(sh, "Loading...");
// 	}

// 	shell_set_bypass(sh, bypass);

// 	return 0;
// }


// static void bypass_cb(const struct shell *sh, uint8_t *recv, size_t len)
// {
// 	uint32_t left_to_read = load_total - load_written;
// 	uint32_t to_write = MIN(len, left_to_read);
//         int rc;

//         k_mutex_lock(&load_lock, K_FOREVER);

//         if (load_ok) {
//                 rc = sbk_image_write(&load_image, load_written, recv, to_write);
//                 if (rc != 0) {
// 		        shell_error(sh, "Write failed at position %x [%d]",
// 			            load_written, rc);
//                         load_ok = false;
// 	        }
//         }

//         load_written += to_write;

// 	if (load_written >= load_total) {
//                 shell_print(sh, "Write complete");
//                 if (load_ok) {
//                         rc = sbk_image_flush(&load_image);
//                 }

// 		set_bypass(sh, NULL);
// 	}

//         k_mutex_unlock(&load_lock);
// }

// static int cmd_load(const struct shell *sh, size_t argc, char *argv[])
// {
// 	uint32_t image_no;

//         image_no = strtoul(argv[1], NULL, 0);
// 	load_total = strtoul(argv[2], NULL, 0);

// 	/* Prepare image for callback. */
// 	if (sbk_os_slot_open(&load_slot, image_no) != 0) {
//                 shell_print(sh, "Error opening slot %d", image_no);
//                 goto end;                
//         }

//         load_ok = true;
//         load_image.ib->bpos = 0U;
//         load_image.ib->bstart = 0U;
//         load_written = 0U;
//         k_mutex_init(&load_lock);
// 	shell_print(sh, "Loading %d bytes to slot %d", load_total, image_no);
// 	set_bypass(sh, bypass_cb);

// end:
// 	return 0;
// }

void cli_load(const struct tshell *tsh, const char *data, size_t len) {
        ldsize -= len;

        if (ldsize == 0U) {
                tshell_set_bypass(tsh, NULL);
        }

        char line[81];

        snprintf(line, sizeof(line), "Waiting for %d OK", ldsize);
        tshell_put(tsh, line);        
}

int cli_command_load(const struct tshell *tsh, int argc, char *argv[]) {
        if (argc < 2) {
                tshell_put(tsh, "Insufficient arguments");
                return 0;
        }

        ldslot = strtoul(argv[1], NULL, 0);
        ldsize = strtoul(argv[2], NULL, 0);
        char line[81];

        snprintf(line, sizeof(line), "Writing %d bytes to slot %d ...", ldsize, ldslot);
        tshell_put(tsh, line);
        tshell_set_bypass(tsh, cli_load);
        tshell_put(tsh, "OK");
        return 0;
}

int cli_command_ilist(const struct tshell *tsh, int argc, char *argv[]) {
        uint32_t slot_no = 0;
        struct sbk_os_slot slot;
        struct sbk_image image = {
                .slot = &slot,
        };
        struct sbk_version version;
	
        while (true) {
                char line[81];
                int rc;

                rc = sbk_os_slot_open(image.slot, slot_no);
                if (rc != 0) {
                        break;
                }
                rc = sbk_image_get_version(&image, &version);
                if (rc != 0) {
                        break;
                }
                snprintf(line, sizeof(line),
                         "Slot %d contains version %d.%d-%d", slot_no,
                         version.major, version.minor, version.revision);
                tshell_put(tsh, line);
                slot_no++;
        }

	return 0;

}

UART_HANDLE_DECLARE(uhndl, DEVICE_DT_GET(DT_CHOSEN(zephyr_console)), 512);
TSHELL_DECLARE(tsh, 64);

TSHELL_REGISTER_CMD(tsh, list, cli_command_ilist, "List images");
TSHELL_REGISTER_CMD(tsh, load, cli_command_load, "Load image to slot: [load slot_no bytes]");
TSHELL_REGISTER_CMD(tsh, reboot, cli_command_reboot, "Reboot device");

void main(void)
{
            
        SBK_LOG_INF("Welcome to %x version %d.%d-%d", shared_data.product_hash,
                shared_data.product_ver.major, 
                shared_data.product_ver.minor,
                shared_data.product_ver.revision);
        SBK_LOG_INF("Running from slot %d", shared_data.bslot);
        SBK_LOG_INF("Boot retries %d", shared_data.bcnt);

        uart_handle_register_rx_cb(&uhndl, tshell_receive, (void *)&tsh);
        tshell_register_send_cb(&tsh, uart_handle_tx, (void *)&uhndl);

        uart_handle_start(&uhndl);
        tshell_start(&tsh);

}