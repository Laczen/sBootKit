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

/**
 * @brief shared data format definition
 */
struct sbk_shared_data {
	uint32_t product_hash;
	struct sbk_version product_ver;
	uint8_t bslot;
	uint8_t bcnt;
	uint8_t mode;
	uint8_t crc8;
};

static struct sbk_shared_data shared_data = {
	.product_ver.major = CONFIG_PVER_MAJ,
	.product_ver.minor = CONFIG_PVER_MIN,
	.product_ver.revision = CONFIG_PVER_REV,
	.bslot = 0U,
	.bcnt = 0U,
};

#define BOOT_RETRIES 4

int main(void)
{
	SBK_LOG_DBG("Welcome...");

	shared_data.product_hash =
		sbk_product_djb2_hash(CONFIG_PNAME, sizeof(CONFIG_PNAME));
	sbk_product_init_hash(&shared_data.product_hash);
	sbk_product_init_version(&shared_data.product_ver);

	struct sbk_slot slot;
	uint8_t start_slot;

	start_slot = shared_data.bslot;
	if (shared_data.bcnt == BOOT_RETRIES) {
		shared_data.bslot++;
		shared_data.bcnt = 0U;
	}

	while (true) {
		struct sbk_image_state st;
		int rc;

		SBK_LOG_DBG("Testing slot %d", shared_data.bslot);
		rc = sbk_open_bootable_slot(&slot, shared_data.bslot);
		if (rc != 0) {
			shared_data.bslot = 0U;
			shared_data.bcnt = 0U;
			continue;
		}

		shared_data.bcnt++;

		rc = sbk_image_can_run(&slot, &st);
		(void)sbk_slot_close(&slot);
		SBK_LOG_DBG("Image state: %x address %x", st.state_flags,
			    st.im.image_start_address);
		if (rc == 0) {
			if ((SBK_IMAGE_STATE_ICONF_IS_SET(st.state_flags)) ||
			    (SBK_IMAGE_STATE_SCONF_IS_SET(st.state_flags))) {
				shared_data.bcnt = 0U;
			}

			SBK_LOG_DBG("Jumping to address: %x bcnt: %d",
				    st.im.image_start_address,
				    shared_data.bcnt);
			sbk_jump_image(st.im.image_start_address);
		}

		shared_data.bslot++;
		if (shared_data.bslot == start_slot) {
			break;
		}
		shared_data.bcnt = 0U;
	}

	SBK_LOG_DBG("No bootable image found");

	while(1);
}
