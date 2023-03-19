/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/shell/shell.h>
#include <zephyr/sys/util.h>
#include "sbk/sbk_os.h"
#include "sbk/sbk_product.h"
#include "sbk/sbk_image.h"

#include <stdlib.h>
#include <string.h>

/* Buffer is only needed for bytes that follow command and offset */
#define BUF_ARRAY_CNT (CONFIG_SHELL_ARGC_MAX - 2)

/* This only issues compilation error when it would not be possible
 * to extract at least one byte from command line arguments, yet
 * it does not warrant successful writes if BUF_ARRAY_CNT
 * is smaller than flash write alignment.
 */
BUILD_ASSERT(BUF_ARRAY_CNT >= 1);

#define IMG_BUF_SIZE 512
static struct k_mutex load_lock;
static uint32_t load_total;
static uint32_t load_written;
static uint8_t img_buffer[IMG_BUF_SIZE];
static struct sbk_os_slot load_slot;
static struct sbk_image_buffer load_image_buf = {
        .buf = img_buffer,
        .blen = IMG_BUF_SIZE,
};
static struct sbk_image load_image = {
        .slot = &load_slot,
        .ib = &load_image_buf,
};
static bool load_ok;

static int set_bypass(const struct shell *sh, shell_bypass_cb_t bypass)
{
	static bool in_use;

	if (bypass && in_use) {
		shell_error(sh, "load supports setting bypass on a single instance.");

		return -EBUSY;
	}

	/* Mark that we have set or unset the bypass function */
	in_use = bypass != NULL;

	if (in_use) {
		shell_print(sh, "Loading...");
	}

	shell_set_bypass(sh, bypass);

	return 0;
}


static void bypass_cb(const struct shell *sh, uint8_t *recv, size_t len)
{
	uint32_t left_to_read = load_total - load_written;
	uint32_t to_write = MIN(len, left_to_read);
        int rc;

        k_mutex_lock(&load_lock, K_FOREVER);

        if (load_ok) {
                rc = sbk_image_write(&load_image, load_written, recv, to_write);
                if (rc != 0) {
		        shell_error(sh, "Write failed at position %x [%d]",
			            load_written, rc);
                        load_ok = false;
	        }
        }

        load_written += to_write;

	if (load_written >= load_total) {
                shell_print(sh, "Write complete");
                if (load_ok) {
                        rc = sbk_image_flush(&load_image);
                }

		set_bypass(sh, NULL);
	}

        k_mutex_unlock(&load_lock);
}

static int cmd_load(const struct shell *sh, size_t argc, char *argv[])
{
	uint32_t image_no;

        image_no = strtoul(argv[1], NULL, 0);
	load_total = strtoul(argv[2], NULL, 0);

	/* Prepare image for callback. */
	if (sbk_os_slot_open(&load_slot, image_no) != 0) {
                shell_print(sh, "Error opening slot %d", image_no);
                goto end;                
        }

        load_ok = true;
        load_image.ib->bpos = 0U;
        load_image.ib->bstart = 0U;
        load_written = 0U;
        k_mutex_init(&load_lock);
	shell_print(sh, "Loading %d bytes to slot %d", load_total, image_no);
	set_bypass(sh, bypass_cb);

end:
	return 0;
}

static int cmd_list(const struct shell *sh, size_t argc, char *argv[])
{
	uint32_t slot_no = 0;
        struct sbk_version version;
	
        while (true) {
                int rc;

                rc = sbk_os_slot_open(load_image.slot, slot_no);
                if (rc != 0) {
                        break;
                }
                rc = sbk_image_get_version(&load_image, &version);
                if (rc != 0) {
                        break;
                }
                shell_print(sh, "Slot %d contains version %d.%d-%d", slot_no,
                            version.major, version.minor, version.revision);
                slot_no++;
        }

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(ldrshell_cmds,
	SHELL_CMD_ARG(load, NULL,
		"<image> <size>",
		cmd_load, 2, 1),
        SHELL_CMD_ARG(list, NULL,
		"list images",
		cmd_list, 0, 1),
	SHELL_SUBCMD_SET_END
);

static int cmd_ldrshell(const struct shell *shell, size_t argc, char **argv)
{
	shell_error(shell, "%s:unknown parameter: %s", argv[0], argv[1]);
	return -EINVAL;
}

SHELL_CMD_ARG_REGISTER(ldrshell, &ldrshell_cmds, "Image loader shell commands",
		       cmd_ldrshell, 2, 0);