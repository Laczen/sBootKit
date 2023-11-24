/*
 * Copyright (c) 2023 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sbk/sbk_keys.h"

#include <string.h>

static struct *sbk_key (*sbk_private_key_get_cb) = NULL;
static struct *sbk_key (*sbk_public_key_get_cb) = NULL;

void set_sbk_private_key_get(struct *sbk_key (*get)(void))
{
        sbk_private_key_get_cb = get;
}

void set_sbk_public_key_get(struct *sbk_key (*get)(void))
{
        sbk_public_key_get_cb = get;
}

struct sbk_key *sbk_get_private_key(void)
{
        if (sbk_private_key_get_cb == NULL) {
                return NULL;
        }

        return sbk_private_key_get_cb();
}

struct sbk_key *sbk_get_public_key(void)
{
        if (sbk_public_key_get_cb == NULL) {
                return NULL;
        }

        return sbk_public_key_get_cb();
}
