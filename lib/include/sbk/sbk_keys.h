/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SBK_KEYS_H_
#define SBK_KEYS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct sbk_key {
	uint8_t *key;
	size_t key_size;
};

void set_sbk_private_key(const struct sbk_key *key);

struct sbk_key *sbk_get_private_key(void);

#ifdef __cplusplus
}
#endif

#endif /* SBK_KEYS_H_*/