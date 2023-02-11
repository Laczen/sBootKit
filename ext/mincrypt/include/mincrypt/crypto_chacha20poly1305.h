/*
 * chacha20 and poly1305 implementation.
 *
 * chacha20 modified from chacha-merged.c ver 20080118 (D. J. Bernstein,
 * Public domain) to reduce code size
 *
 * poly1305 implementation using 32 bit * 32 bit = 64 bit multiplication and 64
 * bit addition. Modified from poly1305-donna-(32) to reduce code size. For the
 * original code see https://github.com/floodyberry/poly1305-donna.
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef CRYPTO_CHACHA20POLY1305_H_
#define CRYPTO_CHACHA20POLY1305_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CRYPTO_CHACHA20_BLOCKSIZE 64

typedef struct {
	uint8_t key[32];
	uint8_t nonce[8];
	uint64_t ic;
} crypto_chacha20_ref_in;

typedef struct {
	uint8_t key[32];
	uint8_t nonce[12];
	uint32_t ic;
} crypto_chacha20_ietf_in;

void chacha20_ref_xor(uint8_t *c, const uint8_t *m, uint64_t clen,
		      crypto_chacha20_ref_in *in);

void chacha20_ietf_xor(uint8_t *c, const uint8_t *m, uint32_t clen,
		       crypto_chacha20_ietf_in *in);

#define CRYPTO_POLY1305_BLOCKSIZE 16

typedef struct {
	uint32_t r[5];
	uint32_t h[5];
	uint32_t pad[4];
        uint32_t bufpos;
	uint8_t buf[CRYPTO_POLY1305_BLOCKSIZE];
} crypto_poly1305_ctx;

void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const uint8_t key[32]);
void crypto_poly1305_update(crypto_poly1305_ctx *ctx, const uint8_t *msg,
                            size_t msglen);
void crypto_poly1305_final(uint8_t mac[16], crypto_poly1305_ctx *ctx);

void crypto_poly1305(uint8_t mac[16], const uint8_t key[32], const uint8_t *msg,
                     size_t msglen);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_CHACHA20POLY1305_H_ */