/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SBK_CRYPTO_H_
#define SBK_CRYPTO_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief crypto API
 * @{
 */

struct sbk_crypto_read_ctx {
	const void *ctx;
	int (*read)(const void *ctx, uint32_t off, void *data, size_t len);
};

struct sbk_crypto_kxch_ctx {
	const void *pkey;
	size_t pkey_size;
	const void *salt;
	size_t salt_size;
	const void *context;
	size_t context_size;
};

struct sbk_crypto_hmac_ctx {
	const void *key;
	size_t key_size;
	const void *hmac;
	size_t hmac_size;
	size_t chunk_size;
};

struct sbk_crypto_sha_ctx {
	const void *sha;
	size_t sha_size;
	size_t chunk_size;
};

struct sbk_crypto_sig_p256_ctx {
	const void *pubkey;
	size_t pubkey_size;
	const void *signature;
	size_t signature_size;
};

struct sbk_crypto_ciphered_read_ctx {
	const struct sbk_crypto_read_ctx *read_ctx;
	const void *key;
	size_t key_size;
};

/**
 * @brief sbk_crypto_cwipe
 *
 * Secure data wipe
 *
 * @param secret: data to wipe
 * @param size: size to wipe
 */
void sbk_crypto_cwipe(void *secret, size_t size);

/**
 * @brief sbk_crypto_compare
 *
 * Secure data compare
 *
 * @param s1: data to compare
 * @param s2: data to compare
 * @param size: size to compare
 */
int sbk_crypto_compare(const void *s1, const void *s2, size_t len);

/**
 * @brief sbk_crypto_hkdf_sha256_kxch
 *
 * Key exchange
 *
 * @param ctx: key exhange context,
 * @param keymaterial: returned key material,
 * @param keymaterial_size: expected size of key material,
 */
void sbk_crypto_hkdf_sha256_kxch(const struct sbk_crypto_kxch_ctx *ctx,
				 void *keymaterial, size_t keymaterial_size);

/**
 * @brief sbk_crypto_hmac_sha256_vrfy
 *
 * Verify hmac_sha256.
 *
 * @param ctx: hmac context
 * @param read_ctx: data read context
 * @param msg_len: length of the message to verify
 * @return 0 if valid, nonzero otherwise
 *
 */
int sbk_crypto_hmac_sha256_vrfy(const struct sbk_crypto_hmac_ctx *hmac_ctx,
				const struct sbk_crypto_read_ctx *read_ctx,
				size_t msg_len);

/**
 * @brief sbk_crypto_sha256_vrfy
 *
 * Verify sha256.
 *
 * @param ctx: sha context
 * @param read_ctx: data read context
 * @param msg_len: length of the message to verify
 * @return 0 if valid, nonzero otherwise
 */
int sbk_crypto_sha256_vrfy(const struct sbk_crypto_sha_ctx *sha_ctx,
			   const struct sbk_crypto_read_ctx *read_ctx,
			   size_t msg_len);

/**
 * @brief sbk_crypto_sig_p256_vrfy
 *
 * Verify p256 signature.
 *
 * @param ctx: sigp256 context
 * @param read_ctx: data read context
 * @param msg_len: length of the message to verify
 * @return 0 if valid, nonzero otherwise
 */
int sbk_crypto_sig_p256_vrfy(const struct sbk_crypto_sig_p256_ctx *sig_ctx,
			     const struct sbk_crypto_read_ctx *read_ctx,
			     size_t msg_len);

size_t sbk_crypto_ciphered_read_km_size(void);

/**
 * @brief sbk_crypto_ciphered_read
 *
 * Read ciphered data, ciphers unencrypted data, unciphers encrypted data
 *
 * @param ctx: ciphered read context
 * @param off: offset from start
 * @param data: output data
 * @param len: length to read
 * @return 0 if OK, nonzero otherwise
 */
int sbk_crypto_ciphered_read(const struct sbk_crypto_ciphered_read_ctx *ctx,
			     uint32_t off, void *data, size_t len);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* SBK_CRYPTO_H_ */
