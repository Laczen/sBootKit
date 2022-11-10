/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SBK_CRYPTO_H_
#define SBK_CRYPTO_H_

#include <stdint.h>

struct sbk_crypto_se {
        void *ctx;
        void *data;
};

#ifdef CONFIG_SBK_TINYCRYPT
#include "tinycrypt/ecc.h"
#include "tinycrypt/aes.h"
#include "tinycrypt/ecc_dh.h"
#include "tinycrypt/ecc_dsa.h"
#include "tinycrypt/sha256.h"
#include "tinycrypt/aes.h"

#define SBK_CRYPTO_FW_SEAL_PUBKEY_SIZE 2 * NUM_ECC_BYTES
#define SBK_CRYPTO_FW_SEAL_SIGNATURE_SIZE 2 * NUM_ECC_BYTES
#define SBK_CRYPTO_FW_SEAL_MESSAGE_SIZE NUM_ECC_BYTES
#define SBK_CRYPTO_FW_SEAL_SIZE SBK_CRYPTO_FW_SEAL_PUBKEY_SIZE +               \
                                SBK_CRYPTO_FW_SEAL_SIGNATURE_SIZE +            \
                                SBK_CRYPTO_FW_SEAL_MESSAGE_SIZE
#define SBK_CRYPTO_FW_HASH_SIZE NUM_ECC_BYTES
#define SBK_CRYPTO_FW_ENC_PUBKEY_SIZE 2 * NUM_ECC_BYTES
#define SBK_CRYPTO_FW_ENC_PRIVKEY_SIZE NUM_ECC_BYTES
#define SBK_CRYPTO_FW_AESCTR_KEY_SIZE TC_AES_KEY_SIZE
#define SBK_CRYPTO_FW_AESCTR_CTR_SIZE TC_AES_KEY_SIZE
#define SBK_CRYPTO_FW_AESCTR_PAR_SIZE SBK_CRYPTO_FW_AESCTR_KEY_SIZE +          \
                                      SBK_CRYPTO_FW_AESCTR_CTR_SIZE
#define SBK_CRYPTO_FW_AESCTR_BLOCK_SIZE TC_AES_BLOCK_SIZE

#endif /* CONFIG_SBK_TINYCRYPT */

#ifdef __cplusplus
extern "C" {
#endif

/** @brief crypto API
 * @{
 */

/**
 * @brief sbk_crypto_get_encr_param
 *
 * Get the parameter used for encryption.
 *
 * @param out_se: returned key and nonce as secure element
 * @param pub_se: public key structure used to generate the shared secret as
 *                secure element
 * @param priv_se: private key used to generate the shared secret as secure
 *                 element
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_crypto_get_encr_param(struct sbk_crypto_se *out_se,
                              const struct sbk_crypto_se *pub_se,
                              const struct sbk_crypto_se *priv_se);

/**
 * @brief sbk_crypto_seal_verify
 *
 * Verifies the firmware seal
 *
 * @param seal: seal data (pubkey, signature, message hash) as secure element
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_crypto_seal_verify(const struct sbk_crypto_se *seal_se);

/**
 * @brief sbk_crypto_msg_from_seal
 *
 * Get a pointer to the message hash from a seal
 *
 * @param seal: seal data (pubkey, signature, message hash) as secure element
 */
uint8_t *sbk_crypto_hash_from_seal(const struct sbk_crypto_se *seal_se);

/**
 * @brief sbk_crypto_hash_verify
 *
 * Verifies a hash to one of multiple hashes.
 *
 * @param hash_se: expected message hash as secure element
 * @param read_cb: read callback function
 * @param read_cb_ctx: read callback context
 * @param len: area size
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_crypto_hash_verify(const struct sbk_crypto_se *hash_se,
                           int (*read_cb)(const void *ctx, uint32_t offset,
                                          void *data,uint32_t len),
                           const void *read_cb_ctx, uint32_t len);

/**
 * @brief sbk_crypto_aes_ctr_mode
 *
 * perform aes ctr calculation
 *
 * @param buf pointer to buffer to encrypt / encrypted buffer
 * @param len bytes to encrypt
 * @param param_se : encryption key and ctr (as secure element)
 * @retval 0 Success
 * @retval -ERRNO errno code if error
 */
int sbk_crypto_aes_ctr_mode(uint8_t *buf, uint32_t len,
                            struct sbk_crypto_se *param_se);

/**
 * @}
 */


#ifdef __cplusplus
}
#endif

#endif /* SBK_CRYPTO_H_ */
