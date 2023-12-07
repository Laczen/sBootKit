/*
 * Copyright (c) 2023 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sbk/sbk_keys.h"

#include <string.h>

static struct sbk_key *private_key = NULL;
static struct sbk_key *public_key = NULL;

void set_sbk_private_key(struct sbk_key *key)
{
	private_key = key;
}

void set_sbk_public_key(struct sbk_key *key)
{
	public_key = key;
}

struct sbk_key *sbk_get_private_key(void)
{
	return private_key;
}

struct sbk_key *sbk_get_public_key(void)
{
	return public_key;
}
