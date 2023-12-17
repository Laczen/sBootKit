/*
 * Copyright (c) 2023 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sbk/sbk_keys.h"

#include <string.h>

static struct sbk_key *private_key = NULL;

void set_sbk_private_key(struct sbk_key *key)
{
	private_key = key;
}

struct sbk_key *sbk_get_private_key(void)
{
	return private_key;
}