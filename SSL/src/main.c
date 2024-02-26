/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "sbk/sbk_slot.h"
#include "sbk/sbk_util.h"
#include "sbk/sbk_tlv.h"
#include "sbk/sbk_image.h"
#include "sbk/sbk_log.h"
#include "sbk/sbk_shell.h"

#define SBK_PRIVATE_KEY                                                         \
	"\x2e\xcc\x34\x06\xc9\xac\xd5\xf1\x66\x02\x8d\xb1\x91\xbc\x1c\x5f"      \
	"\x08\x53\x76\xda\xc0\xe9\xd2\xaf\xab\x37\x66\x65\x1d\x67\x89\x66"

#define SBK_PUBLIC_KEY \
        "\x76\x15\x7c\xa9\x1b\xd0\x64\xc5\xf4\x5f\xda\xaa\xf8\xab\x31\xfa" \
        "\xa8\x49\xcb\x7f\x12\x84\xbe\x79\x98\xd3\xa9\x55\xef\x9a\x27\xee" \
        "\x6c\xae\xf0\x42\x70\x3e\x96\x50\xac\xc7\x0d\xe4\x5f\xf3\xf5\x4b" \
        "\x99\xf7\x9c\x49\xe3\x1c\x79\x3b\x59\x4b\x43\x38\x41\xa4\xb6\x81"

#define BOOT_RETRIES 4

// bool get_booteable_image(struct sbk_image_info *info, uint8_t *idx)
// {
// 	struct sbk_slot slot;
// 	struct sbk_image_info walk;
// 	size_t sltcnt = 0U;
// 	bool rv = false;

// 	while (sbk_open_rimage_slot(&slot, sltcnt) == 0) {
// 		sltcnt++;
// 		(void)sbk_slot_close(&slot);
// 	}

// 	while (sltcnt != 0) {
// 		sltcnt--;
// 		if (sbk_open_rimage_slot(&slot, sltcnt) != 0) {
// 			continue;
// 		}

// 		SBK_IMAGE_STATE_CLR(walk.state, SBK_IMAGE_STATE_FULL);
// 		sbk_image_sfsl_state(&slot, &walk);
// 		(void)sbk_slot_close(&slot);

// 		if (!SBK_IMAGE_STATE_ISSET(walk.state, SBK_IMAGE_STATE_SBOK)) {
// 			continue;
// 		}

// 		if (!rv) {
// 			memcpy(info, &walk, sizeof(walk));
// 			*idx = sltcnt;
// 			rv = true;
// 		}

// 		if (walk.image_sequence_number > info->image_sequence_number) {
// 			memcpy(info, &walk, sizeof(walk));
// 			*idx = sltcnt;
// 		}
// 	}

// 	return rv;
// }

/**
 * @brief sbk_shell interface
 *
 */
int cli_cmd_reboot(const struct sbk_shell *sh, int argc, char *argv[])
{
	struct sbk_bootinfo bootinfo;
	uint32_t slot, bootcnt;

	if (argc < 2) {
		sbk_shell_fprintf(sh, "Insufficient arguments");
		return 0;
	}

	slot = strtoul(argv[1], NULL, 0);
        bootcnt = strtoul(argv[2], NULL, 0);

	bootinfo.idx = (uint8_t)slot;
	bootinfo.cnt = (uint8_t)bootcnt;

	(void)sbk_tlv_set_bootinfo(&bootinfo);
	sbk_shell_fprintf(sh, "Rebooting\n");

	sbk_reboot();
	return 0;
}

int cli_cmd_info(const struct sbk_shell *sh, int argc, char *argv[])
{
	size_t sltcnt;
	struct sbk_slot slot;
	struct sbk_image_state_info state_info;

	sltcnt = 0U;
	while (sbk_open_image_slot(&slot, sltcnt) == 0) {
		sltcnt++;
		(void)sbk_slot_close(&slot);
	}

	sbk_shell_fprintf(sh, "Image slots (%d):\r\n", sltcnt);
	while (sltcnt != 0) {
		sltcnt--;
		if (sbk_open_image_slot(&slot, sltcnt) != 0) {
			continue;
		}

		sbk_image_ssl_state(&slot, &state_info);
		(void)sbk_slot_close(&slot);
		sbk_shell_fprintf(sh, "slt %d: state %x\r\n", sltcnt,
				  state_info.state);
	}

	sltcnt = 0U;
	while (sbk_open_update_slot(&slot, sltcnt) == 0) {
		sltcnt++;
		(void)sbk_slot_close(&slot);
	}

	sbk_shell_fprintf(sh, "Update slots (%d):\r\n", sltcnt);
	while (sltcnt != 0) {
		sltcnt--;
		if (sbk_open_update_slot(&slot, sltcnt) != 0) {
			continue;
		}

		sbk_image_ssl_state(&slot, &state_info);
		(void)sbk_slot_close(&slot);
		sbk_shell_fprintf(sh, "slt %d: state %x\r\n", sltcnt,
				  state_info.state);
	}

	sltcnt = 0U;
	while (sbk_open_backup_slot(&slot, sltcnt) == 0) {
		sltcnt++;
		(void)sbk_slot_close(&slot);
	}

	sbk_shell_fprintf(sh, "Backup slots (%d):\r\n", sltcnt);
	while (sltcnt != 0) {
		sltcnt--;
		if (sbk_open_backup_slot(&slot, sltcnt) != 0) {
			continue;
		}

		sbk_image_ssl_state(&slot, &state_info);
		(void)sbk_slot_close(&slot);
		sbk_shell_fprintf(sh, "slt %d: state %x\r\n", sltcnt,
				  state_info.state);
	}

	return 0;
}

int cli_bypass_test(const struct sbk_shell *sh, const void *data, size_t len)
{
	sbk_shell_fprintf(sh, "bypass called\r\n");
	return 1;
}

int cli_cmd_bypass(const struct sbk_shell *sh, int argc, char *argv[])
{

	if (argc < 2) {
		sbk_shell_fprintf(sh, "Insufficient arguments");
		return 0;
	}

	sbk_shell_fprintf(sh, "Going to bypass mode: ");
	sbk_shell_set_bypass(sh, cli_bypass_test);
	sbk_shell_fprintf(sh, "OK\n");
	return 0;
}

static struct sbk_upload_ctx {
	struct sbk_slot destination;
	uint32_t image_sequence_number;
	uint8_t buffer[1024];
	size_t bstart;
	size_t bpos;
	size_t rem;
	bool ldok;
} upload_ctx;

int upload_slot_read(const void *ctx, uint32_t offset, void *data, size_t len)
{
	const struct sbk_upload_ctx *upload_ctx =
		(const struct sbk_upload_ctx *)ctx;
	int rc;
	
	if (offset < upload_ctx->bstart) {
		size_t rdlen = SBK_MIN(len, upload_ctx->bstart - offset);
		rc = sbk_slot_read(&upload_ctx->destination, offset, data, len);
		if (rc != 0) {
			goto end;
		}
		len -= rdlen;
	}

	if (len != 0U) {
		offset -= upload_ctx->bstart;
		memcpy(data, &upload_ctx->buffer[offset], len);
	}

	rc = 0;
end:
	return rc;
}

int upload_slot_address(const void *ctx, uint32_t *address)
{
	const struct sbk_upload_ctx *upload_ctx =
		(const struct sbk_upload_ctx *)ctx;

	return sbk_slot_address(&upload_ctx->destination, address);
}

int cli_upload_bypass(const struct sbk_shell *sh, const void *data, size_t len)
{
	const size_t bsize = sizeof(upload_ctx.buffer);
	struct sbk_slot slot = {
		.ctx = (void *)&upload_ctx,
		.read = upload_slot_read,
		.address = upload_slot_address,
		.prog = NULL,
		.close = NULL,
	};
	uint8_t *data8 = (uint8_t *)data;
        int rc;

        while (len != 0) {
                unsigned long boff = upload_ctx.bpos & (bsize - 1);
                size_t cplen = SBK_MIN(len, bsize - boff);

                memcpy(&upload_ctx.buffer[boff], data8, cplen);
                boff += cplen;
                len -= cplen;
		upload_ctx.bpos +=cplen;
                upload_ctx.rem -= cplen;
                data8 += cplen;

		slot.size = upload_ctx.bpos;

                if (slot.size == bsize) {
                        sbk_shell_fprintf(sh, "Checking image\r\n");
			struct sbk_image_state_info state_info;

			sbk_image_ssl_state(&slot, &state_info);
			sbk_shell_fprintf(sh, "Image state %x\r\n", state_info.state);
			if (!SBK_IMAGE_STATE_ISSET(state_info.state,
						   SBK_IMAGE_STATE_SSL_DU_OK)) {
				sbk_shell_fprintf(sh, "bad image\r\n");
                                upload_ctx.ldok = false;
                        }

			if (state_info.image_sequence_number < 
			    upload_ctx.image_sequence_number) {
				sbk_shell_fprintf(sh, "bad image sequence number\r\n");
				upload_ctx.ldok = false;
			}
                }

                if (((boff == bsize) || (upload_ctx.rem == 0U)) && 
		    (upload_ctx.ldok)) {
			sbk_shell_fprintf(sh, "Writing to flash ...\r\n");
                        rc = sbk_image_read(&slot, upload_ctx.bstart,
					    &upload_ctx.buffer[0], boff);
                        if (rc != 0) {
                                upload_ctx.ldok = false;
                                sbk_shell_fprintf(sh, "Read failed");
                        }

			rc = sbk_slot_prog(&upload_ctx.destination,
					   upload_ctx.bstart,
					   &upload_ctx.buffer[0], boff);
			if (rc != 0) {
                                upload_ctx.ldok = false;
                                sbk_shell_fprintf(sh, "Write failed");
                        }

			if (boff == bsize) {
				upload_ctx.bstart += boff;
			}
                }
        }

        if (((upload_ctx.bpos % 512) == 0) || (upload_ctx.rem == 0U)) {
                sbk_shell_fprintf(sh, "off: %ld, rs: %d OK\r\n", upload_ctx.bpos,
				  upload_ctx.rem);
        }

	if (upload_ctx.rem == 0U) {
		
                sbk_slot_close(&upload_ctx.destination);
                sbk_shell_set_bypass(sh, NULL);
        }

	return 0;
}

int cli_cmd_upload(const struct sbk_shell *sh, int argc, char *argv[]) {
        uint32_t slot;
	size_t ldsize;
	struct sbk_image_state_info state_info;

        if (argc < 2) {
                sbk_shell_fprintf(sh, "Insufficient arguments");
                return 0;
        }

        slot = strtoul(argv[1], NULL, 0);
        ldsize = strtoul(argv[2], NULL, 0);

        if (sbk_open_image_slot(&upload_ctx.destination, slot) != 0) {
                sbk_shell_fprintf(sh, "Bad slot specified");
                return 0;
        }

	state_info.image_sequence_number = 0U;
	sbk_image_ssl_state(&upload_ctx.destination, &state_info);

	upload_ctx.image_sequence_number = state_info.image_sequence_number;
        if (upload_ctx.destination.size < ldsize) {
                sbk_shell_fprintf(sh, "Image to large");
                return 0;
        }

	upload_ctx.bstart = 0U;
        upload_ctx.bpos = 0U;
	upload_ctx.rem = ldsize;
	upload_ctx.ldok = true;
        
        sbk_shell_set_bypass(sh, NULL);
        sbk_shell_set_bypass(sh, cli_upload_bypass);
	sbk_shell_fprintf(sh, "Writing %d bytes to slot %d ...", ldsize, slot);
        sbk_shell_fprintf(sh, "OK\r\n");
        return 0;
}

static const struct sbk_shell_cmd shell_commands[] = {
	{"reboot", cli_cmd_reboot, "Reboot the device"},
	{"info", cli_cmd_info, "Get image info"},
	{"bypass", cli_cmd_bypass, "Say hello"},
	{"upload", cli_cmd_upload, "Upload image [slot] [size]"},
	{"help", sbk_shell_help_handler, "Lists all commands"},
};

SBK_SHELL_DEFINE(tst, shell_commands, 5);

bool swap_images(void)
{
	struct sbk_slot slot;
	uint32_t sltcnt = 0;
	bool rv = false;

	while (sbk_open_image_slot(&slot, sltcnt) == 0) {
		sltcnt++;
		(void)sbk_slot_close(&slot);
	}

	// while ((sltcnt != 0) && (!rv)) {
	// 	sltcnt--;
	// 	if (sbk_image_sfsl_swap(sltcnt)) {
	// 		rv = true;
	// 	}
	// }

	return rv;
}

int main(void)
{

	const struct sbk_key private_key = {
		.key = SBK_PRIVATE_KEY,
		.key_size = sizeof(SBK_PRIVATE_KEY) - 1,
	};
	const struct sbk_key public_key = {
		.key = SBK_PUBLIC_KEY,
		.key_size = sizeof(SBK_PUBLIC_KEY) - 1,
	};	

	int64_t timeout = sbk_uptime_get() + 4000;
	
	set_sbk_private_key(&private_key);
	set_sbk_public_key(&public_key);

	if (swap_images()) {
		sbk_reboot();
	}

	sbk_shell_init_transport(tst);

	while (sbk_uptime_get() < timeout) {
		if (sbk_shell_receive(tst)) {
			timeout = sbk_uptime_get() + 100000;
		}
	}

	sbk_reboot();
	return 0;
}
