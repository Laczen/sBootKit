/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <string.h>

#include "sbk/sbk_slot.h"
#include "sbk/sbk_util.h"
#include "sbk/sbk_tlv.h"
#include "sbk/sbk_image.h"
#include "sbk/sbk_log.h"

#define BOOT_RETRIES 4

bool get_booteable_image(struct sbk_image_info *info, uint8_t *idx, bool test)
{
	struct sbk_slot slot;
	struct sbk_image_info walk;
	size_t sltcnt = 0U;
	bool rv = false;

	while (sbk_open_rimage_slot(&slot, sltcnt) == 0) {
		sltcnt++;
		(void)sbk_slot_close(&slot);
	}

	if (sltcnt == 1) {
		test = true;
	}

	while (sltcnt != 0) {
		sltcnt--;
		if (sbk_open_rimage_slot(&slot, sltcnt) != 0) {
			continue;
		}

		SBK_IMAGE_STATE_CLR(walk.state, SBK_IMAGE_STATE_FULL);
		sbk_image_sfsl_state(&slot, &walk);
		(void)sbk_slot_close(&slot);

		if (test) {
			SBK_IMAGE_STATE_SET(walk.state, SBK_IMAGE_STATE_ICNF);
		}

		if (!SBK_IMAGE_STATE_ISSET(walk.state, SBK_IMAGE_STATE_SBOK)) {
			continue;
		}

		
		if (!rv) {
			memcpy(info, &walk, sizeof(walk));
			*idx = sltcnt;
			rv = true;
		}

		if (walk.image_sequence_number > info->image_sequence_number) {
			memcpy(info, &walk, sizeof(walk));
			*idx = sltcnt;
		}
	}

	return rv;
}

bool get_sldr_image(struct sbk_image_info *info)
{
	struct sbk_slot slot;
	bool rv = false;

	if (sbk_open_sldr_slot(&slot) != 0) {
		goto end;
	}

	sbk_image_sfsl_state(&slot, info);
	(void)sbk_slot_close(&slot);
	if (SBK_IMAGE_STATE_ISSET(info->state, SBK_IMAGE_STATE_SBOK)) {
		rv = true;
	}

end:
	return rv;
}

int main(void)
{
	bool boot = false;
	struct sbk_tlv_bootinfo bootinfo;
	struct sbk_image_info info;

	SBK_LOG_DBG("Welcome...");
	SBK_LOG_DBG("Available RAM: %d", CONFIG_SRAM_SIZE);

	if ((sbk_tlv_get_bootinfo(&bootinfo) == 0) && 
	    (bootinfo.cmd != SBK_BOOTINFO_CMDSLDR) &&
	    (bootinfo.cnt != 0U)) {
		bool test = (bootinfo.cmd == SBK_BOOTINFO_CMDTEST); 
		
		bootinfo.cnt--;
		boot = get_booteable_image(&info, &bootinfo.idx, test);
	}

	if (!boot) {
		boot = get_sldr_image(&info);
	}

	if (boot) {
		bootinfo.cmd = SBK_BOOTINFO_CMDNONE;
		(void)sbk_tlv_set_bootinfo(&bootinfo);

		SBK_LOG_DBG("Jumping to address: %x", info.image_start_address);
		sbk_boot_prep(info.image_start_address);
		sbk_jump_image(info.image_start_address);
	}

	SBK_LOG_DBG("No bootable image found");

	while (true)
		;
}
