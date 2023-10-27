/*
 * Copyright (c) 2023 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sbk/sbk_boot.h"
#include "sbk/sbk_slot.h"
#include "sbk/sbk_image.h"
#include "sbk/sbk_util.h"
#include "sbk/sbk_log.h"

static void sbk_boot_upgrade(void)
{

}

/*
 * Get the next alternative idx: find the next idx that has the highest
 * authorisation counter but is smaller then the authorisation counter of idx
 *
 */
static int sbk_boot_get_alt_idx(uint8_t *idx)
{
	return 0;
}

void sbk_boot_get_image_state(uint8_t idx, bool alt, bool upg,
			      struct sbk_image_state *st)
{
	uint8_t
        bool upgraded = false;

        while (true) {
                if ((upg) && (!upgraded)) {
                        sbk_upgrade();
                        upgraded = true;
                }

                if (alt) {
                        if (sbk_boot_get_alt_idx(idx);
                        alt = false;
                }

                struct sbk_slot bslot;
		int rc;

		SBK_LOG_DBG("Testing slot %d", idx);
		if (sbk_open_bootable_slot(&bslot, idx) != 0) {
                        break;
                }

		SBK_IMAGE_STATE_CLR_FLAGS(st->state_flags);
		if ((sbk_image_get_state_fsl(&bslot, &st) != 0) ||
                    (!SBK_IMAGE_STATE_CAN_BOOT(st->state_flags))) {
                        if (!upgraded) {
                                upg = true;
                        } else {
                                alt = true;
                        }
                }

                (void)sbk_slot_close(&bslot);
                if ((!upg) && (!alt)) {
                        return;
                }
        }
}
