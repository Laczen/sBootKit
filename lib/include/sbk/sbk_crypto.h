/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SBK_CRYPTO_H_
#define SBK_CRYPTO_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SBK_CRYPTO_KXCH_BUF_SIZE 64
#define SBK_CRYPTO_AUTH_BUF_SIZE 16 + 15 * 4
#define SBK_CRYPTO_KM_BUF_SIZE 44


/** @brief crypto API
 * @{
 */

/**
 * @brief sbk_crypto_cwipe
 *
 * clear a crypto buffer.
 *
 * @retval state size
 */
void sbk_crypto_cwipe(void *secret, size_t size);

/**
 * @brief sbk_crypto_kxch_init
 *
 * Key exchange init phase - generate prk
 *
 * @param prk: returned pseudo random key,
 * @param ktag: key tag used to identify private key,
 * @param salt: salt used in the prk generation,
 * @param salt_size:
 * @retval 1 if key_idx to large,
 * @retval 0 if succesfull
 */
int sbk_crypto_kxch_init(void *prk, unsigned int key_idx, const uint8_t *salt,
                          size_t salt_size);

/**
 * @brief sbk_crypto_kxch_final
 *
 * Key exchange final phase - generate keymaterial and clear prk
 *
 * @param keymaterial: generated key material
 * @param prk: input pseudo random key,
 * @param context: key material context (what will it be used for),
 * @param context_size:
 */
void sbk_crypto_kxch_final(void *keymaterial, void *prk, const uint8_t *context,
                           size_t context_size);

/**
 * @brief sbk_crypto_auth_state_size
 *
 * Get the authentication state size.
 *
 * @retval state size
 */
size_t sbk_crypto_auth_state_size(void);

/**
 * @brief sbk_crypto_auth_init
 *
 * Initialize an authentication request.
 *
 * @param state: authentication state
 */
void sbk_crypto_auth_init(void *state);

/**
 * @brief sbk_crypto_auth_update
 *
 * Update authentication.
 *
 * @param state: authentication state
 * @param data: data
 * @param len: data size
 */
void sbk_crypto_auth_update(void *state, void *data, size_t len);

/**
 * @brief sbk_crypto_auth_final
 *
 * Check the authentication tag.
 *
 * @param tag: expected tag
 * @param state: authentication state
 * @retval -ERRNO errno code if tag does not match,
 * @retval 0 if succesfull
 *
 */
int sbk_crypto_auth_final(const void *tag, void *state);


/**
 * @}
 */


#ifdef __cplusplus
}
#endif

#endif /* SBK_CRYPTO_H_ */
