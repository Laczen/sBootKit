/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "sbk/sbk_crypto.h"
#include "sbk/sbk_util.h"

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
static inline bool sbk_crypto_se_valid(const struct sbk_crypto_se *se)
{
        return true;
}
#endif

#ifdef CONFIG_SBK_TINYCRYPT
int sbk_crypto_seal_verify(const struct sbk_crypto_se *seal_se)
{
        if (!sbk_crypto_se_valid(seal_se)) {
                return -SBK_EC_EFAULT;
        }

        const struct uECC_Curve_t * curve = uECC_secp256r1();
        const uint8_t *pubkey = (const uint8_t *)seal_se->data;
        const uint8_t *sign = pubkey + SBK_CRYPTO_FW_SEAL_PUBKEY_SIZE;
        const uint8_t *msg = sign + SBK_CRYPTO_FW_SEAL_SIGNATURE_SIZE;
        const uint32_t msg_size = SBK_CRYPTO_FW_SEAL_MESSAGE_SIZE;
        int rc;

        if (uECC_verify(pubkey, msg, msg_size, sign, curve) == 0) {
                rc = -SBK_EC_EFAULT;
                goto end;
        }

        rc = 0;
end:
        return rc;
}

const uint8_t *sbk_crypto_digest_from_seal(const struct sbk_crypto_se *seal_se)
{
        uint8_t *ret = (uint8_t *)seal_se->data;

        ret += SBK_CRYPTO_FW_SEAL_PUBKEY_SIZE;
        ret += SBK_CRYPTO_FW_SEAL_SIGNATURE_SIZE;
        return ret;
}

int sbk_crypto_seal_pkey_verify(const struct sbk_crypto_se *seal_se,
                                const uint8_t *pkey)
{
        if (memcmp(seal_se->data, pkey, SBK_CRYPTO_FW_SEAL_PUBKEY_SIZE) != 0) {
                return -SBK_EC_EFAULT;
        }

        return 0;
}
#endif /* CONFIG_SBK_TINYCRYPT */

#ifdef CONFIG_SBK_TINYCRYPT
int sbk_crypto_digest_verify(const struct sbk_crypto_se *digest_se,
                             int (*read_cb)(const void *ctx, uint32_t offset,
                                            void *data, uint32_t len),
                             const void *read_cb_ctx, uint32_t len)
{
        if (!sbk_crypto_se_valid(digest_se)) {
                return -SBK_EC_EFAULT;
        }

        const uint8_t *digest = (const uint8_t *)digest_se->data;
        struct tc_sha256_state_struct s;
        uint8_t buf[SBK_CRYPTO_FW_HASH_SIZE];
        uint32_t offset = 0U;
        int rc = 0;

        if (tc_sha256_init(&s) == 0) {
                rc = -SBK_EC_EFAULT;
                goto end;
        }

        while (len) {
                uint32_t rdlen = SBK_MIN(len, sizeof(buf));
                rc = read_cb(read_cb_ctx, offset, buf, rdlen);
                if (rc != 0) {
                        goto end;
                }

                if (tc_sha256_update(&s, buf, rdlen) == 0) {
                        rc = -SBK_EC_EFAULT;
                        goto end;
                }

                len -= rdlen;
                offset += rdlen;
        }

        if (tc_sha256_final(buf, &s) == 0) {
                rc = -SBK_EC_EFAULT;
                goto end;
        }

        if (memcmp(digest, buf, SBK_CRYPTO_FW_HASH_SIZE) != 0) {
                rc = -SBK_EC_EFAULT;
        }

end:
        return rc;
}
#endif /* CONFIG_SBK_TINYCRYPT */

#ifdef CONFIG_SBK_TINYCRYPT
int sbk_crypto_get_encr_param(struct sbk_crypto_se *out_se,
                              const struct sbk_crypto_se *pub_se,
                              const struct sbk_crypto_se *priv_se)
{
        if ((!sbk_crypto_se_valid(out_se)) || (!sbk_crypto_se_valid(pub_se)) ||
            (!sbk_crypto_se_valid(priv_se))) {
                return -SBK_EC_EFAULT;
        }

        uint8_t *param = (uint8_t *)out_se->data;
        uint8_t *pubkey = (uint8_t *)pub_se->data;
        uint8_t *privkey = (uint8_t *)priv_se->data;
        uint8_t ext[4] = {0};
        uint8_t secret[SBK_CRYPTO_FW_ENC_PRIVKEY_SIZE] = {0};
        const struct uECC_Curve_t * curve = uECC_secp256r1();
        struct tc_sha256_state_struct s;
        int rc;

        if (uECC_valid_public_key(pubkey, curve) != 0) {
                rc = -SBK_EC_EFAULT;
                goto end;
        }

        if (uECC_shared_secret(pubkey, privkey, secret, curve) == 0) {
                rc = -SBK_EC_EFAULT;
                goto end;
        }

        if (tc_sha256_init(&s) == 0) {
                rc = -SBK_EC_EFAULT;
                goto end;
        }

        if (tc_sha256_update(&s, secret, sizeof(secret)) == 0) {
                rc = -SBK_EC_EFAULT;
                goto end;
        }

        if (tc_sha256_update(&s, ext, 4) == 0) {
                rc = -SBK_EC_EFAULT;
                goto end;
        }

        if (tc_sha256_final(param, &s) == 0) {
                rc = -SBK_EC_EFAULT;
                goto end;
        }

        rc = 0;
end:
        return rc;
}
#endif /* CONFIG_SBK_TINYCRYPT */

#ifdef CONFIG_SBK_TINYCRYPT
int sbk_crypto_aes_ctr_mode(uint8_t *buf, uint32_t len,
                            struct sbk_crypto_se *param_se)
{
        if (!sbk_crypto_se_valid(param_se)) {
                return -SBK_EC_EFAULT;
        }

        const uint8_t *key = (const uint8_t *)param_se->data;
        uint8_t *iv = (uint8_t *)param_se->data + SBK_CRYPTO_FW_AESCTR_KEY_SIZE;
        struct tc_aes_key_sched_struct sched;
        uint8_t buffer[SBK_CRYPTO_FW_AESCTR_BLOCK_SIZE];
        uint8_t u8;
        int rc;

        (void)tc_aes128_set_encrypt_key(&sched, key);
        for (uint32_t i = 0U; i < len; i++) {
                uint32_t blk_off = i & (sizeof(buffer) - 1);
                if (blk_off == 0U) {
                        if (!tc_aes_encrypt(buffer, iv, &sched)) {
                                rc = -SBK_EC_EFAULT;
                                goto end;
                        }

                        /* Update IV */
                        uint32_t j = SBK_CRYPTO_FW_AESCTR_CTR_SIZE;
                        while (j != 0) {
                                if (++(*(iv + j - 1)) != 0U) {
                                        break;
                                }
                                j--;
                        }

                }

                /* update output */
                u8 = *buf;
                *buf++ = u8 ^ buffer[blk_off];
        }

        rc = 0;
end:
        return rc;
}
#endif /* CONFIG_SBK_TINYCRYPT */
