/*
 * Copyright (c) 2019 Laczen
 * Copyright (c) 2017 Nordic Semiconductor ASA
 * Copyright (c) 2015 Runtime Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include "sbk/sbk_crypto.h"

struct digest_rd_ctx {
        uint8_t *buffer;
        uint32_t buffer_size;
};

int digest_read(const void *ctx, uint32_t offset, void *data, uint32_t len)
{
        struct digest_rd_ctx *rd_ctx = (struct digest_rd_ctx *)ctx;

        if ((offset + len) > rd_ctx->buffer_size) {
                return -1;
        }

        memcpy(data, rd_ctx->buffer + offset, len);
        return 0;
}

ZTEST_SUITE(sbk_crypto_tests, NULL, NULL, NULL, NULL, NULL);

extern uint8_t test_msg[];
extern uint8_t test_msg_bytes;
extern uint8_t test_msg_digest[];
extern uint8_t test_msg_digest_bytes;

/**
 * @brief Test digest calculation
 */
ZTEST(sbk_crypto_tests, sbk_digest)
{
        int err;
        struct digest_rd_ctx ctx = {
                .buffer = test_msg,
                .buffer_size = SBK_CRYPTO_FW_HASH_SIZE,
        };
	struct sbk_crypto_se digest_se = {
		.data = test_msg_digest,
	};

	err = sbk_crypto_digest_verify(&digest_se, &digest_read, (void *)&ctx,
                		       test_msg_bytes);
	zassert_true(err == 0, "Digest differs");
}

extern uint8_t test_signature[];
extern uint8_t ec256_root_pub_key[];

/**
 * @brief Test signature verification
 */
ZTEST(sbk_crypto_tests, sbk_sign_verify)
{
	int err;
	uint8_t tmp;
	uint8_t seal[SBK_CRYPTO_FW_SEAL_SIZE];
	uint8_t *slptr = &seal[0];
	struct sbk_crypto_se seal_se = {
		.data = slptr,
	};

	memcpy(slptr, &ec256_root_pub_key[0], SBK_CRYPTO_FW_SEAL_PUBKEY_SIZE);
	slptr += SBK_CRYPTO_FW_SEAL_PUBKEY_SIZE;
	memcpy(slptr, &test_signature[0], SBK_CRYPTO_FW_SEAL_SIGNATURE_SIZE);
	slptr += SBK_CRYPTO_FW_SEAL_SIGNATURE_SIZE;
	memcpy(slptr, &test_msg_digest[0], SBK_CRYPTO_FW_SEAL_MESSAGE_SIZE);
	err = sbk_crypto_seal_verify(&seal_se);
	zassert_true(err == 0, "Signature validation failed: [err %d]", err);

	/* modify the message digest */
	tmp = test_msg_digest[0];
	test_msg_digest[0] >>=1;
	memcpy(slptr, &test_msg_digest[0], SBK_CRYPTO_FW_SEAL_MESSAGE_SIZE);
	err = sbk_crypto_seal_verify(&seal_se);
	zassert_false(err == 0, "Invalid hash generates valid signature");

	/* reset the message digest */
	test_msg_digest[0] = tmp;
}

extern uint8_t test_enc_pubkey[];
extern uint8_t test_enc_key[];
extern uint8_t ec256_boot_pri_key[];

/**
 * @brief Test the generation of an encryption key from public key
 */
ZTEST(sbk_crypto_tests, sbk_gen_encr_param)
{
	int err;
	uint8_t param[32], tmp;
	struct sbk_crypto_se out_se = {
		.data = &param[0],
	};
	const struct sbk_crypto_se pubk_se = {
		.data = &test_enc_pubkey[0],
	};
	const struct sbk_crypto_se priv_se = {
		.data = &ec256_boot_pri_key[0],
	};

	err = sbk_crypto_get_encr_param(&out_se, &pubk_se, &priv_se);
	zassert_true(err == 0,  "Failed to get encryption key: [err %d]", err);
	err = memcmp(param, test_enc_key, 16);
	zassert_true(err == 0,  "Encryption keys differ: [err %d]", err);

	/* modify the key */
	tmp = test_enc_pubkey[0];
	test_enc_pubkey[0] >>= 1;
	err = sbk_crypto_get_encr_param(&out_se, &pubk_se, &priv_se);
	zassert_false(err == 0,  "Invalid pubkey generates encryption key");

	/* reset the key */
	test_enc_pubkey[0] = tmp;
}

extern uint8_t test_msg[];
extern uint8_t test_msg_bytes;
extern uint8_t ec256_boot_pri_key[];

/**
 * @brief Test the aes routines
 */
ZTEST(sbk_crypto_tests, sbk_aes)
{
	uint8_t enc_test_msg[test_msg_bytes];
	uint8_t dec_test_msg[test_msg_bytes];
	uint8_t param[SBK_CRYPTO_FW_AESCTR_PAR_SIZE];
	uint8_t *paramptr = &param[0];
	struct sbk_crypto_se param_se = {
		.data = paramptr,
	};
	uint8_t aes_bc = test_msg_bytes/SBK_CRYPTO_FW_AESCTR_BLOCK_SIZE;
	int err;

	memcpy(paramptr, &ec256_boot_pri_key[0], SBK_CRYPTO_FW_AESCTR_KEY_SIZE);
	paramptr += SBK_CRYPTO_FW_AESCTR_KEY_SIZE;
	memset(paramptr, 0, SBK_CRYPTO_FW_AESCTR_CTR_SIZE);

	memcpy(enc_test_msg, test_msg, test_msg_bytes);
	err = sbk_crypto_aes_ctr_mode(enc_test_msg, test_msg_bytes, &param_se);
	zassert_true(err == 0,  "AES CTR returned [err %d]", err);
	err = param[SBK_CRYPTO_FW_AESCTR_PAR_SIZE - 1] - aes_bc;
	zassert_true(err == 0,  "AES CTR wrong CTR value");
	err = memcmp(enc_test_msg, test_msg, test_msg_bytes);
	zassert_false(err == 0,  "AES wrong encrypt data");

	memset(paramptr, 0, SBK_CRYPTO_FW_AESCTR_CTR_SIZE);
	memcpy(dec_test_msg, enc_test_msg, test_msg_bytes);
	err = sbk_crypto_aes_ctr_mode(dec_test_msg, test_msg_bytes, &param_se);
	zassert_true(err == 0,  "AES CTR returned [err %d]", err);
	err = param[SBK_CRYPTO_FW_AESCTR_PAR_SIZE - 1] - aes_bc;
	zassert_true(err == 0,  "AES CTR wrong CTR value");
	err = memcmp(dec_test_msg, test_msg, test_msg_bytes);
	zassert_true(err == 0,  "AES wrong decrypt data");
}