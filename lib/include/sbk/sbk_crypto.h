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

/**
 * @brief sbk_crypto_cwipe
 *
 * clear a crypto buffer.
 *
 * @retval state size
 */
void sbk_crypto_cwipe(void *secret, size_t size);

size_t sbk_crypto_kxch_prk_size(void);
size_t sbk_crypto_kxch_km_size(void);

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

size_t sbk_crypto_auth_block_size(void);
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

size_t sbk_crypto_cipher_block_size(void);
size_t sbk_crypto_cipher_key_size(void);
size_t sbk_crypto_cipher_nonce_size(void);
size_t sbk_crypto_cipher_state_size(void);

/**
 * @brief sbk_crypto_cipher_init
 *
 * Initialize an cipher request.
 *
 * @param state: cipher state
 * @param km: key material (key-nonce) used for cipher,
 * @param km_size:
 * @param cnt: block counter
 */
void sbk_crypto_cipher_init(void *state, const void *km, size_t km_size, 
                            uint32_t cnt);

/**
 * @brief sbk_crypto_cipher
 *
 * cipher the data (this erases the state).
 *
 * @param state: cipher state
 * @param data: data ciphered during operation
 * @param len: data size
 */
void sbk_crypto_cipher(void *state, void *data, size_t len);

/**
 * @}
 */


#ifdef __cplusplus
}
#endif

#endif /* SBK_CRYPTO_H_ */
