/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sbk/sbk_boot.h"
#include "sbk/sbk_manifest.h"
#include "sbk/sbk_move.h"

static bool sbk_boot_new_manifest(void) {
        return true;
}

static int sbk_boot_get_validated_bslot(void)
{
        return 1;
}

void sbk_boot(void)
{
        bool manifest_move;
        uint32_t bslot = 0;

        /* Step 1: continue manifest move if needed */
        (void)sbk_move_manifest();

        /* Step 2: move the manifest if required and all is ok */
        if (sbk_boot_new_manifest()) {
                (void)sbk_move_manifest();
        }

        /* Step 3: continue or start image moves */
        (void)sbk_move();

        /* Step 4: validate manifest and get boot slot */
        bslot = sbk_boot_get_validated_bslot();

        if (bslot != 0) {
                sbk_os_jump_image(bslot);
        }

}