/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <string.h>

#include "sbk/sbk_slot.h"
#include "sbk/sbk_util.h"
#include "sbk/sbk_product.h"
#include "sbk/sbk_image.h"
#include "sbk/sbk_boot.h"
#include "sbk/sbk_log.h"

#ifndef CONFIG_PNAME
#define CONFIG_PNAME "TEST"
#endif
#ifndef CONFIG_PVER_MAJ
#define CONFIG_PVER_MAJ 0
#endif
#ifndef CONFIG_PVER_MIN
#define CONFIG_PVER_MIN 0
#endif
#ifndef CONFIG_PVER_REV
#define CONFIG_PVER_REV 0
#endif

static struct sbk_version product_version = {
	.major = CONFIG_PVER_MAJ,
	.minor = CONFIG_PVER_MIN,
	.revision = CONFIG_PVER_REV,
};

static struct sbk_product product = {
	.name = CONFIG_PNAME,
	.name_size = sizeof(CONFIG_PNAME) - 1,
	.version = &product_version,
};

#define BOOT_RETRIES 4

bool get_booteable_image(struct sbk_image_state *st)
{
	struct sbk_slot slot;
	struct sbk_image_state walk;
	bool rv = false;

	for (uint8_t slotnr = 0U; slotnr <= 128; slotnr++) {
		if (sbk_open_rimage_slot(&slot, slotnr) != 0) {
			break;
		}

		SBK_IMAGE_STATE_CLR(walk.state, SBK_IMAGE_STATE_FULL);
		sbk_image_sfsl_state(&slot, &walk);
		(void)sbk_slot_close(&slot);
		if (!SBK_IMAGE_STATE_ISSET(walk.state, SBK_IMAGE_STATE_SBOK)) {
			continue;
		}

		if (!rv) {
			st->info = walk.info;
			st->state = walk.state;
			rv = true;
		}

		if (walk.info.image_sequence_number >
		    st->info.image_sequence_number) {
			st->info = walk.info;
			st->state = walk.state;
		}
	}

	return rv;
}

bool get_sldr_image(struct sbk_image_state *st)
{
	struct sbk_slot slot;
	bool rv = false;

	if (sbk_open_sldr_slot(&slot) != 0) {
		goto end;
	}

	sbk_image_sfsl_state(&slot, st);
	(void)sbk_slot_close(&slot);
	if (SBK_IMAGE_STATE_ISSET(st->state, SBK_IMAGE_STATE_SBOK)) {
		rv = true;
	}

end:
	return rv;
}

int main(void)
{
	bool boot;
	struct sbk_image_state st;

	SBK_LOG_DBG("Welcome...");
	sbk_set_product(&product);

	boot = !sbk_image_sfsl_sldr_needed();

	if (boot) {
		boot = get_booteable_image(&st);
	} else {
		boot = get_sldr_image(&st);
	}

	if (boot) {
		SBK_LOG_DBG("Jumping to address: %x",
			    st.info.image_start_address);
		sbk_jump_image(st.info.image_start_address);
	}

	SBK_LOG_DBG("No bootable image found");

	while (true)
		;
}
