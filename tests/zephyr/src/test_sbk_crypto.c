/*
 * Copyright (c) 2019 Laczen
 * Copyright (c) 2017 Nordic Semiconductor ASA
 * Copyright (c) 2015 Runtime Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ztest.h>
#include "sbk/sbk_crypto.h"

extern uint8_t test_msg[];
extern uint8_t test_msg_hash[];

struct hash_rd_ctx {
        uint8_t *buffer;
        uint32_t buffer_size;
};

int hash_read(const void *ctx, uint32_t offset, void *data, uint32_t len)
{
        struct hash_rd_ctx *rd_ctx = (struct hash_rd_ctx *)ctx;

        if ((offset + len) > rd_ctx->buffer_size) {
                return -1;
        }

        memcpy(data, rd_ctx->buffer + offset, len);
        return 0;
}

/**
 * @brief Test hash calculation for data in flash
 */
void test_sbk_hash(void)
{
        int err;
        struct hash_rd_ctx ctx = {
                .buffer = test_msg,
                .buffer_size = DIGEST_BYTES
        };

	err = sbk_digest_verify(test_msg_hash, &hash_read, (void *)&ctx, 
                                DIGEST_BYTES);
	zassert_true(err == 0, "Hash differs");
}

extern uint8_t test_signature[];

/**
 * @brief Test signature verification
 */
void test_sbk_sign_verify(void)
{
	int err;
	uint8_t tmp;

	err = sbk_sign_verify(test_msg_hash, test_signature);
	zassert_true(err == 0, "Signature validation failed: [err %d]", err);

	/* modify the key */
	tmp = test_msg_hash[0];
	test_msg_hash[0] >>=1;
	err = sbk_sign_verify(test_msg_hash, test_signature);
	zassert_false(err == 0, "Invalid hash generates valid signature");

	/* reset the key */
	test_msg_hash[0] = tmp;

}

extern uint8_t test_enc_pub_key[];
extern uint8_t test_enc_key[];

/**
 * @brief Test the generation of an encryption key from public key
 */
void test_sbk_get_encr_key(void)
{
	int err;
	uint8_t enc_key[16], nonce[16], tmp;

	err = sbk_get_encr_key(enc_key, nonce, test_enc_pub_key, 16);
	zassert_true(err == 0,  "Failed to get encryption key: [err %d]", err);
	err = memcmp(enc_key, test_enc_key, 16);
	zassert_true(err == 0,  "Encryption keys differ: [err %d]", err);

	/* modify the key */
	tmp = test_enc_pub_key[0];
	test_enc_pub_key[0] >>= 1;
	err = sbk_get_encr_key(enc_key, nonce, test_enc_pub_key, 16);
	zassert_false(err == 0,  "Invalid pubkey generates encryption key");

	/* reset the key */
	test_enc_pub_key[0] = tmp;
}

extern uint8_t test_msg[];
extern uint8_t ec256_boot_pri_key[];
uint8_t enc_test_msg[DIGEST_BYTES];
uint8_t dec_test_msg[DIGEST_BYTES];

/**
 * @brief Test the aes enc routine
 */
void test_sbk_aes_enc(void)
{
	int err;

	uint8_t ctr[AES_BLOCK_SIZE]={0};

	memcpy(enc_test_msg, test_msg, DIGEST_BYTES);
	err = sbk_aes_ctr_mode(enc_test_msg, DIGEST_BYTES, ctr,
			      ec256_boot_pri_key);
	zassert_true(err == 0,  "AES CTR returned [err %d]", err);
	err = ctr[15] - DIGEST_BYTES/AES_BLOCK_SIZE;
	zassert_true(err == 0,  "AES CTR wrong CTR value");
	err = memcmp(enc_test_msg, test_msg, DIGEST_BYTES);
	zassert_false(err == 0,  "AES wrong encrypt data");

}

void test_sbk_aes_dec(void)
{
	int err;
	uint8_t ctr[AES_BLOCK_SIZE]={0};

	memcpy(dec_test_msg, enc_test_msg, DIGEST_BYTES);
	err = sbk_aes_ctr_mode(dec_test_msg, DIGEST_BYTES, ctr,
			      ec256_boot_pri_key);
	zassert_true(err == 0,  "AES CTR returned [err %d]", err);
	err = ctr[15] - DIGEST_BYTES/AES_BLOCK_SIZE;
	zassert_true(err == 0,  "AES CTR wrong CTR value");
	err = memcmp(dec_test_msg, test_msg, DIGEST_BYTES);
	zassert_true(err == 0,  "AES wrong decrypt data");

}

extern uint32_t test_msg_crc32;

void test_sbk_crc32(void)
{
        int err;

        err = sbk_crc32(0x0, test_msg, DIGEST_BYTES) - test_msg_crc32;
	zassert_true(err == 0, "CRC32 differs");

}

void test_sbk_crypto(void)
{
	ztest_test_suite(test_sbk_crypto,
			 ztest_unit_test(test_sbk_aes_enc),
			 ztest_unit_test(test_sbk_aes_dec),
			 ztest_unit_test(test_sbk_hash),
			 ztest_unit_test(test_sbk_sign_verify),
			 ztest_unit_test(test_sbk_get_encr_key),
                         ztest_unit_test(test_sbk_crc32)
	);

	ztest_run_test_suite(test_sbk_crypto);
}