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

#define CRYPTO_SHA256_BLOCKSIZE 32

#if defined(__cplusplus)
extern "C" {
#endif

///////////
// SHA26 //
///////////
typedef struct {
	uint64_t count;
	uint8_t buf[64];
	uint32_t state[8];
} crypto_sha256_ctx;

void crypto_sha256_init(crypto_sha256_ctx *ctx);
void crypto_sha256_update(crypto_sha256_ctx *ctx, const void *in, size_t inlen);
void crypto_sha256_final(void *out, crypto_sha256_ctx *ctx);

// Convenience method.
void crypto_sha256(void *out, const void *in, size_t inlen);

////////////////
// HMAC-SHA26 //
////////////////
typedef struct {
	crypto_sha256_ctx sha256_ctx;
	uint8_t key[64];
} crypto_hmac_sha256_ctx;

void crypto_hmac_sha256_init(crypto_hmac_sha256_ctx *ctx, const void *key,
			     size_t keylen);
void crypto_hmac_sha256_update(crypto_hmac_sha256_ctx *ctx, const void *in,
			       size_t inlen);
void crypto_hmac_sha256_final(void *out, crypto_hmac_sha256_ctx *ctx);

// Convenience method.
void crypto_hmac_sha256(void *out, const void *key, size_t keylen,
			const void *in, size_t inlen);

////////////////
// HKDF-SHA26 //
////////////////
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