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

#define SBK_CRYPTO_KXCH_PRK_SIZE 32
#define SBK_CRYPTO_KXCH_KM_SIZE 44


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
 * @brief sbk_crypto_kxch_prk_size
 * 
 * @return size_t pseudo random key size 
 */
inline size_t sbk_crypto_kxch_prk_size(void)
{
        return SBK_CRYPTO_KXCH_PRK_SIZE;
}

/**
 * @brief sbk_crypto_kxch_init
 *
 * Key exchange initialize
 *
 * @param prk: returned pseudo random key,
 * @param salt: salt used in the prk generation,
 * @param salt_size:
 */
void sbk_crypto_kxch_init(void *prk, const void *salt, size_t salt_size);

/**
 * @brief sbk_crypto_kxch_km_size
 * 
 * @return size_t key material size 
 */
inline size_t sbk_crypto_kxch_km_size(void)
{
        return SBK_CRYPTO_KXCH_KM_SIZE;
}

/**
 * @brief sbk_crypto_kxch_final
 *
 * Key exchange finalize
 *
 * @param keymaterial: returned keymaterial (of size SBK_CRYPTO_KM_SIZE)
 * @param prk: returned pseudo random key,
 * @param context: context used in the keymaterial generation,
 * @param context_size:
 */
void sbk_crypto_kxch_final(void *keymaterial, const void *prk,
                           const void *context, size_t context_size);

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
 * @param key: key used for authentication,
 * @param key_size:
 */
void sbk_crypto_auth_init(void *state, const void *key, size_t key_size);

/**
 * @brief sbk_crypto_auth_update
 *
 * Update authentication.
 *
 * @param state: authentication state
 * @param data: data
 * @param len: data size
 */
void sbk_crypto_auth_update(void *state, const void *data, size_t len);

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
