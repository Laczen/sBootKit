/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "sbk/sbk_crypto.h"
#include "mincrypt/crypto_sha256.h"
#include "mincrypt/crypto_chacha20poly1305.h"

void sbk_crypto_cwipe(void *secret, size_t size)
{
	volatile uint8_t *v_secret = (uint8_t *)secret;
	for (size_t i = 0; i < size; i++) {
		v_secret[i] = 0U;
	}
}

int sbk_crypto_compare(const void *s1, const void *s2, size_t len)
{
	uint8_t *s1_8 = (uint8_t *)s1;
	uint8_t *s2_8 = (uint8_t *)s2;
	int rc = 0;

	for (size_t i = 0; i < len; i++) {
		rc |= s1_8[i] ^ s2_8[i];
	}

	return rc;
}

size_t sbk_crypto_kxch_prk_size(void)
{
	return crypto_hkdf_sha256_prk_size();
}

size_t sbk_crypto_kxch_km_size(void)
{
	return crypto_chacha20_ietf_key_size() +
	       crypto_chacha20_ietf_nonce_size();
}

void sbk_crypto_kxch_init(void *prk, const void *salt, size_t salt_size,
			  const void *pkey, size_t pkey_size)
{
	crypto_hkdf_sha256_extract(prk, salt, salt_size, pkey, pkey_size);
}

void sbk_crypto_kxch_final(void *keymaterial, const void *prk,
			   const void *context, size_t context_size)
{
	crypto_hkdf_sha256_expand(keymaterial, prk, context, context_size,
				  sbk_crypto_kxch_km_size());
}

size_t sbk_crypto_auth_block_size(void)
{
	return crypto_hmac_sha256_block_size();
}

size_t sbk_crypto_auth_state_size(void)
{
	return crypto_hmac_sha256_state_size();
}

void sbk_crypto_auth_init(void *state, const void *key, size_t key_size)
{
	crypto_hmac_sha256_init(state, key, key_size);
}

void sbk_crypto_auth_update(void *state, const void *data, size_t len)
{
	crypto_hmac_sha256_update(state, data, len);
}

void sbk_crypto_auth_final(void *tag, void *state)
{
	crypto_hmac_sha256_final(tag, state);
	sbk_crypto_cwipe(state, sbk_crypto_auth_state_size());
}

size_t sbk_crypto_cipher_block_size(void)
{
	return crypto_chacha20_ietf_block_size();
}

size_t sbk_crypto_cipher_key_size(void)
{
	return crypto_chacha20_ietf_key_size();
}

size_t sbk_crypto_cipher_nonce_size(void)
{
	return crypto_chacha20_ietf_nonce_size();
}

size_t sbk_crypto_cipher_state_size(void)
{
	return crypto_chacha20_ietf_state_size();
}

void sbk_crypto_cipher_init(void *state, const void *km, size_t km_size,
			    uint32_t cnt)
{
	uint8_t *key = (uint8_t *)km;
	uint8_t *nonce = key + sbk_crypto_cipher_key_size();

	return crypto_chacha20_ietf_init(state, key, nonce, cnt);
}

void sbk_crypto_cipher(void *out, const void *in, size_t len, void *state)
{
	crypto_chacha20_ietf_xor((uint8_t *)out, (const uint8_t *)in, len,
				 state);
}
