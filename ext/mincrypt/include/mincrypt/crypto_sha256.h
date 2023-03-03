/*
 * sha256 implementation
 *
 * Modified from mincrypt, extended to support hmac and hkdf. For the original
 * code https://github.com/topjohnwu/mincrypt/
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef CRYPTO_SHA256_H_
#define CRYPTO_SHA256_H_

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

///////////
// SHA26 //
///////////
#define CRYPTO_SHA256_BLOCKSIZE 32

size_t crypto_sha256_state_size(void);
size_t crypto_sha256_block_size(void);
void crypto_sha256_init(void *state);
void crypto_sha256_update(void *state, const void *in, size_t inlen);
void crypto_sha256_final(void *out, void *state);

// Convenience method.
void crypto_sha256(void *out, const void *in, size_t inlen);

////////////////
// HMAC-SHA26 //
////////////////
#define CRYPTO_HMAC_SHA256_BLOCKSIZE 32

size_t crypto_hmac_sha256_state_size(void);
size_t crypto_hmac_sha256_block_size(void);
void crypto_hmac_sha256_init(void *state, const void *key, size_t keylen);
void crypto_hmac_sha256_update(void *state, const void *in, size_t inlen);
void crypto_hmac_sha256_final(void *out, void *state);

// Convenience method.
void crypto_hmac_sha256(void *out, const void *key, size_t keylen,
			const void *in, size_t inlen);

////////////////
// HKDF-SHA26 //
////////////////
size_t crypto_hkdf_sha256_prk_size(void);
void crypto_hkdf_sha256_extract(void *prk, const void *salt, size_t saltlen,
				const void *key, size_t keylen);
void crypto_hkdf_sha256_expand(void *out, const void *prk, const void *lbl,
			       size_t lbllen, size_t len);

// Convenience method.
void crypto_hkdf_sha256(void *out, const void *salt, size_t saltlen,
			const void *key, size_t keylen, const void *lbl,
			size_t lbllen, size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CRYPTO_SHA256_H_ */