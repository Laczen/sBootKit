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

bool get_booteable_image(const struct sbk_slot *slot,
		         struct sbk_image_state_info *info)
{
	bool rv = false;

	sbk_watchdog_feed();
	sbk_image_fsl_state(slot, info);

	if (SBK_IMAGE_STATE_ISSET(info->state, SBK_IMAGE_STATE_FSLOK)) {
		rv = true;
	}

	return rv;
}

int main(void)
{
	bool boot = false;
	struct sbk_bootinfo bootinfo;
	struct sbk_slot slot;
	struct sbk_image_state_info info;

	SBK_LOG_DBG("FSL...");

	sbk_watchdog_init();
	sbk_watchdog_feed();

	if ((sbk_tlv_get_bootinfo(&bootinfo) == 0) && 
	    (bootinfo.cnt != 0U) &&
	    (sbk_open_rimage_slot(&slot, bootinfo.idx) == 0)) {
		bootinfo.cnt--;
		boot = get_booteable_image(&slot, &info);
		(void)sbk_slot_close(&slot);	
	}

	SBK_LOG_DBG("FSL fallback stage 1");
	if (!boot) { /* fallback to second stage loader */
		bootinfo.cnt = 0U;
		bootinfo.idx = 0U;
		if (sbk_open_ssl_slot(&slot) == 0) {
			boot = get_booteable_image(&slot, &info);
			(void)sbk_slot_close(&slot);
		}
	}

	SBK_LOG_DBG("FSL fallback stage 2");
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
