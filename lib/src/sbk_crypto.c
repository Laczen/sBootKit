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
#include "private_key.h"

void sbk_crypto_cwipe(void *secret, size_t size)
{
	volatile uint8_t *v_secret = (uint8_t *)secret;
	for (size_t i = 0; i < size; i++) {
                v_secret[i] = 0U;
        }
}

static int sbk_crypto_compare(const void *res, const void *exp, size_t len)
{
        uint8_t *res8 = (uint8_t *)res;
        uint8_t *exp8 = (uint8_t *)exp;
        int rc = 0;

        for (size_t i = 0; i < len; i++) {
                rc |= exp8[i]^res8[i];
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

void sbk_crypto_kxch_init(void *prk, const void *salt, size_t salt_size)
{
        crypto_hkdf_sha256_extract(prk, salt, salt_size, SBK_PRIV_KEY,
                                   sizeof(SBK_PRIV_KEY) - 1);
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

int sbk_crypto_auth_final(const void *tag, void *state)
{
        uint8_t ctag[sbk_crypto_auth_block_size()];

        crypto_hmac_sha256_final(ctag, state);

        return sbk_crypto_compare(tag, ctag, sizeof(ctag));
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

        return crypto_chacha20_ietf_init(state, key, nonce, cnt + 1);
}

void sbk_crypto_cipher(void *state, void *data, size_t len)
{
        crypto_chacha20_ietf_xor((uint8_t *)data, NULL, len, state);
}
