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

#define CRYPTO_CHACHA20_REF_BLOCKSIZE 64
#define CRYPTO_CHACHA20_REF_KEYSIZE 32
#define CRYPTO_CHACHA20_REF_NONCESIZE 8

size_t crypto_chacha20_ref_block_size(void);
size_t crypto_chacha20_ref_key_size(void);
size_t crypto_chacha20_ref_nonce_size(void);
size_t crypto_chacha20_ref_state_size(void);
void crypto_chacha20_ref_init(void *state, const uint8_t *key,
			      const uint8_t *nonce, uint64_t ic);
void crypto_chacha20_ref_xor(uint8_t *c, const uint8_t *m, uint64_t clen,
		      	     void *state);

#define CRYPTO_CHACHA20_IETF_BLOCKSIZE 64
#define CRYPTO_CHACHA20_IETF_KEYSIZE 32
#define CRYPTO_CHACHA20_IETF_NONCESIZE 12

size_t crypto_chacha20_ietf_block_size(void);
size_t crypto_chacha20_ietf_key_size(void);
size_t crypto_chacha20_ietf_nonce_size(void);
size_t crypto_chacha20_ietf_state_size(void);
void crypto_chacha20_ietf_init(void *state, const uint8_t *key,
		               const uint8_t *nonce, uint32_t ic);
void crypto_chacha20_ietf_xor(uint8_t *c, const uint8_t *m, uint32_t clen,
		              void *state);

#define CRYPTO_POLY1305_BLOCKSIZE 16
#define CRYPTO_POLY1305_KEYSIZE 32

size_t crypto_poly1305_block_size(void);
size_t crypto_poly1305_key_size(void);
size_t crypto_poly1305_state_size(void);
void crypto_poly1305_init(void *state, const uint8_t *key);
void crypto_poly1305_update(void *state, const uint8_t *msg, size_t msglen);
void crypto_poly1305_flush(void *state);
void crypto_poly1305_final(uint8_t *mac, void *state);

void crypto_poly1305(uint8_t *mac, const uint8_t *key, const uint8_t *msg,
		     size_t msglen);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_CHACHA20POLY1305_H_ */