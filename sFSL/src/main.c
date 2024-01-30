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

bool get_booteable_image(const struct sbk_slot *slot, struct sbk_image_info *info)
{
	bool rv = false;

	SBK_IMAGE_STATE_CLR(info->state, SBK_IMAGE_STATE_FULL);
	sbk_image_sfsl_state(slot, info);

	if (SBK_IMAGE_STATE_ISSET(info->state, SBK_IMAGE_STATE_SBOK)) {
		rv = true;
	}

	return rv;
}

int main(void)
{
	bool boot = false;
	struct sbk_tlv_bootinfo bootinfo;
	struct sbk_slot slot;
	struct sbk_image_info info;

	SBK_LOG_DBG("Welcome...");
	SBK_LOG_DBG("Available RAM: %d", CONFIG_SRAM_SIZE);

	sbk_watchdog_init();
	sbk_watchdog_feed();

	if ((sbk_tlv_get_bootinfo(&bootinfo) == 0) && 
	    (bootinfo.cnt != 0U) &&
	    (sbk_open_rimage_slot(&slot, bootinfo.idx) == 0)) {
		bootinfo.cnt--;
		boot = get_booteable_image(&slot, &info);
		(void)sbk_slot_close(&slot);	
	}

	if (!boot) { /* fallback to secure loader */
		bootinfo.cnt = 0U;
		bootinfo.idx = 0U;
		if (sbk_open_sldr_slot(&slot) == 0) {
			boot = get_booteable_image(&slot, &info);
			(void)sbk_slot_close(&slot);
		}
	}

	while (!boot) { /* fallback to first runnable image */
		if (sbk_open_rimage_slot(&slot, bootinfo.idx) != 0) {
			break;
		}

		boot = get_booteable_image(&slot, &info);
		(void)sbk_slot_close(&slot);
		if (!boot) {
			bootinfo.idx++;
		}
	}

	if (boot) {
		(void)sbk_tlv_set_bootinfo(&bootinfo);

		SBK_LOG_DBG("Jumping to address: %x", info.image_start_address);
		sbk_boot_prep(info.image_start_address);
		sbk_jump_image(info.image_start_address);
	}

	SBK_LOG_DBG("No bootable image found");

	while (true)
		;
}
