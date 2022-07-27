/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SBK_CRYPTO_H_
#define SBK_CRYPTO_H_

#include <stdint.h>

#ifdef CONFIG_SBK_TINYCRYPT
#include "tinycrypt/ecc.h"
#include "tinycrypt/aes.h"
#include "tinycrypt/ecc_dh.h"
#include "tinycrypt/ecc_dsa.h"
#include "tinycrypt/sha256.h"
#include "tinycrypt/aes.h"
#define AES_BLOCK_SIZE		TC_AES_BLOCK_SIZE
#define AES_KEY_SIZE		TC_AES_KEY_SIZE
#define SIGNATURE_BYTES		2 * NUM_ECC_BYTES
#define PUBLIC_KEY_BYTES	2 * NUM_ECC_BYTES
#define PRIVATE_KEY_BYTES	NUM_ECC_BYTES
#define SHARED_SECRET_BYTES	NUM_ECC_BYTES
#define VERIFY_BYTES		NUM_ECC_BYTES
#define DIGEST_BYTES		NUM_ECC_BYTES
#endif /* CONFIG_SBK_TINYCRYPT */

#ifdef __cplusplus
extern "C" {
#endif

/** @brief crypto API
 * @{
 */

/**
 * @brief sbk_get_encr_key
 *
 * Get the key and nonce used for encryption using a ec_dh 256 key exchange.
 * The key and nonce are derived from the shared secret using a key derivation
 * function (i.e. KDF1).
 * This routine uses the bootloader private key.
 *
 * @param key: returned encryption key
 * @param nonce: returned nonce
 * @param pubkey: public key used to generate the shared secret
 * @param keysize: expected size of returned key and nonce (i.e AES block size)
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_get_encr_key(uint8_t *key, uint8_t *nonce, const uint8_t *pubkey,
                     uint32_t keysize);

/**
 * @brief sbk_sign_verify
 *
 * Verifies the signature given the hash for a ec_dsa 256 signing.
 * This routine uses the public root keys that are stored in the bootloader.
 *
 * @param digest: calculated message digest
 * @param signature: message hash signature
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_sign_verify(const uint8_t *digest, const uint8_t *signature);

/**
 * @brief sbk_digest_verify
 *
 * Verifies the digest.
 *
 * @param digest: calculated message digest
 * @param read_cb: read callback function
 * @param read_cb_ctx: read callback context
 * @param len: area size
 * @retval -ERRNO errno code if error
 * @retval 0 if succesfull
 */
int sbk_digest_verify(const uint8_t *digest, int (*read_cb)(const void *ctx,
		      uint32_t offset, void *data, uint32_t len),
                      const void *read_cb_ctx, uint32_t len);

/**
 * @brief sbk_aes_ctr_mode
 *
 * perform aes ctr calculation
 *
 * @param buf pointer to buffer to encrypt / encrypted buffer
 * @param len bytes to encrypt
 * @param ctr counter (as byte array)
 * @param key encryption key
 * @retval 0 Success
 * @retval -ERRNO errno code if error
 */
int sbk_aes_ctr_mode(uint8_t *buf, uint32_t len, uint8_t *ctr, 
                     const uint8_t *key);

/**
 * @brief sbk_crc32
 *
 * perform crc32 calculation
 *
 * @param crc start value
 * @param data pointer to data to calculate crc32 on
 * @param len buf length
 * @retval calculated crc32
 */
uint32_t sbk_crc32(uint32_t crc, const void *data, uint32_t len);
/**
 * @}
 */


#ifdef __cplusplus
}
#endif

/* Some default settings () */
#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE		16
#endif
#ifndef AES_KEY_SIZE
#define AES_KEY_SIZE		16
#endif
#ifndef SIGNATURE_BYTES
#define SIGNATURE_BYTES		64
#endif
#ifndef PUBLIC_KEY_BYTES
#define PUBLIC_KEY_BYTES	64
#endif
#ifndef PRIVATE_KEY_BYTES
#define PRIVATE_KEY_BYTES	32
#endif
#ifndef SHARED_SECRET_BYTES
#define SHARED_SECRET_BYTES	32
#endif
#ifndef VERIFY_BYTES
#define VERIFY_BYTES		32
#endif
#ifndef DIGEST_BYTES
#define DIGEST_BYTES		32
#endif

#endif
