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

struct sbk_key *sbk_get_private_key(void);

struct sbk_key *sbk_get_public_key(void);

#ifdef __cplusplus
}
#endif

#endif /* SBK_KEYS_H_*/