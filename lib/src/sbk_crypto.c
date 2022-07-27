/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <string.h>

#include "sbk/sbk_crypto.h"
#include "sbk/sbk_util.h"

extern const uint8_t ec256_boot_pri_key[];
extern const uint32_t ec256_boot_pri_key_len;
extern const uint8_t ec256_root_pub_key[];
extern const uint32_t ec256_root_pub_key_len;

#ifdef CONFIG_SBK_TINYCRYPT
/* The default_CSPRNG is used to improve side channel attacks for
 * uECC_shared_secret(). As this is only used internally we can savely
 * set the default_CSPRNG() to do nothing
 */
int default_CSPRNG(uint8_t *dest, unsigned int size) {
        return 1;
}
#endif

#ifdef CONFIG_SBK_TINYCRYPT
int sbk_get_encr_key(uint8_t *key, uint8_t *nonce, const uint8_t *pubkey,
                     uint32_t keysize)
{
        uint8_t ext[4] = {0};
        uint8_t secret[SHARED_SECRET_BYTES] = {0};
        uint8_t digest[DIGEST_BYTES] = {0};
        const struct uECC_Curve_t * curve = uECC_secp256r1();
        struct tc_sha256_state_struct s;

        if (keysize > PRIVATE_KEY_BYTES) {
                return -SBK_EC_EFAULT;
        }

        if (uECC_valid_public_key(pubkey, curve) != 0) {
                return -SBK_EC_EFAULT;
        }

        if (uECC_shared_secret(pubkey, ec256_boot_pri_key, secret, curve) == 0) {
                return -SBK_EC_EFAULT;
        }

        if (tc_sha256_init(&s) == 0) {
                return -SBK_EC_EFAULT;
        }

        if (tc_sha256_update(&s, secret, SHARED_SECRET_BYTES) == 0) {
                return -SBK_EC_EFAULT;
        }

        if (tc_sha256_update(&s, ext, 4) == 0) {
                return -SBK_EC_EFAULT;
        }

        if (tc_sha256_final(digest, &s) == 0) {
                return -SBK_EC_EFAULT;
        }
        memcpy(key, digest, keysize);
        memcpy(nonce, digest+keysize, keysize);

        return 0;
}
#endif /* CONFIG_SBK_TINYCRYPT */

#ifdef CONFIG_SBK_TINYCRYPT
int sbk_sign_verify(const uint8_t *hash, const uint8_t *signature)
{
        const struct uECC_Curve_t * curve = uECC_secp256r1();
        const uint32_t rpkl = ec256_root_pub_key_len;
        uint8_t pubk[PUBLIC_KEY_BYTES];

        /* validate the hash for each of the root pubkeys */
        for (uint32_t cnt = 0U; cnt < rpkl; cnt += PUBLIC_KEY_BYTES) {
                memcpy(pubk, &ec256_root_pub_key[cnt], PUBLIC_KEY_BYTES);
                if (uECC_valid_public_key(pubk, curve) != 0) {
                        continue;
                }
                if (uECC_verify(pubk, hash, VERIFY_BYTES, signature, curve)) {
                        return 0;
                }
        }
        return -SBK_EC_EFAULT;
}
#endif /* CONFIG_SBK_TINYCRYPT */

#ifdef CONFIG_SBK_TINYCRYPT
int sbk_digest_verify(const uint8_t *digest, int (*read_cb)(const void *ctx,
                      uint32_t offset, void *data, uint32_t len), 
                      const void *read_cb_ctx, uint32_t len)
{
        int rc;
        struct tc_sha256_state_struct s;
        uint8_t buf[DIGEST_BYTES];
        uint32_t offset = 0U;
        
        if (tc_sha256_init(&s) == 0) {
                return -SBK_EC_EFAULT;
        }

        while (len) {
                uint32_t rdlen = SBK_MIN(len, sizeof(buf));
                rc = read_cb(read_cb_ctx, offset, buf, rdlen);
                if (rc != 0) {
                        return rc;
                }

                if (tc_sha256_update(&s, buf, rdlen) == 0) {
                        return -SBK_EC_EFAULT;
                }

                len -= rdlen;
                offset += rdlen;
        }

        if (tc_sha256_final(buf, &s) == 0) {
                return -SBK_EC_EFAULT;
        }

        return memcmp(digest, buf, DIGEST_BYTES) == 0 ? 0 : -SBK_EC_EFAULT;

}
#endif /* CONFIG_SBK_TINYCRYPT */

#ifdef CONFIG_SBK_TINYCRYPT
int sbk_aes_ctr_mode(uint8_t *buf, uint32_t len, uint8_t *ctr, 
                     const uint8_t *key)
{
        struct tc_aes_key_sched_struct sched;
        uint8_t buffer[AES_BLOCK_SIZE];
        uint8_t nonce[AES_BLOCK_SIZE];
        uint32_t i;
        uint8_t blk_off, j, u8;

        (void)memcpy(nonce, ctr, sizeof(nonce));
        (void)tc_aes128_set_encrypt_key(&sched, key);
        for (i = 0; i < len; i++) {
                blk_off = i & (AES_BLOCK_SIZE - 1);
                if (blk_off == 0) {
                        if (tc_aes_encrypt(buffer, nonce, &sched)) {
                                for (j = AES_BLOCK_SIZE; j > 0; --j) {
                                        if (++nonce[j - 1] != 0) {
                                                    break;
                                        }
                                    }
                        } else {
                                return -SBK_EC_EFAULT;
                        }
                }
                /* update output */
                u8 = *buf;
                *buf++ = u8 ^ buffer[blk_off];
        }
        (void)memcpy(ctr, nonce, sizeof(nonce));

        return 0;
}
#endif /* CONFIG_SBK_TINYCRYPT */

/* Software CRC implementation with small lookup table */
uint32_t sbk_crc32(uint32_t crc, const void *data, uint32_t len) {
        const uint8_t *data8 = (uint8_t *)data;
        /* crc table generated from polynomial 0xedb88320 */
        static const uint32_t table[16] = {
                0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
                0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
                0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
                0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c,
        };

        crc = ~crc;

        for (size_t i = 0; i < len; i++) {
                uint8_t byte = data8[i];

                crc = (crc >> 4) ^ table[(crc ^ byte) & 0x0f];
                crc = (crc >> 4) ^ table[(crc ^ ((uint32_t)byte >> 4)) & 0x0f];
        }

        return (~crc);
}

