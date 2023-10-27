/*
 * Copyright (c) 2023 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sbk/sbk_util.h"

uint8_t sbk_crc8(uint8_t crc, void *data, size_t len)
{
        static const uint8_t kvs_crc8_ccitt_table[16] = {
		0x00, 0x07, 0x0e, 0x09, 0x1c, 0x1b, 0x12, 0x15,
		0x38, 0x3f, 0x36, 0x31, 0x24, 0x23, 0x2a, 0x2d
	};
	const uint8_t *p = data;
	size_t i;

	for (i = 0; i < len; i++) {
		crc ^= p[i];
		crc = (crc << 4) ^ kvs_crc8_ccitt_table[crc >> 4];
		crc = (crc << 4) ^ kvs_crc8_ccitt_table[crc >> 4];
	}

	return crc;
}
