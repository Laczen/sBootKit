/*
 * sha256 tests
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mincrypt/crypto_sha256.h"
#include "mincrypt_test/crypto_sha256_tvectors.h"

static int compare(void *res, void *exp, size_t len)
{
        uint8_t *res8 = (uint8_t *)res;
        uint8_t *exp8 = (uint8_t *)exp;
        int rc = 0;

        for (size_t i = 0; i < len; i++) {
                rc |= exp8[i]^res8[i];
        }

        return rc;
}

/* Test Vector sha256 #1 */
#define TEST_VECTOR_SHA256_01_MSG \
        "\x61\x62\x63"

#define TEST_VECTOR_SHA256_01_RES \
        "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23" \
        "\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad"

/* Test Vector sha256 #2 */
#define TEST_VECTOR_SHA256_02_MSG ""

#define TEST_VECTOR_SHA256_02_RES \
        "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24" \
        "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55"

/* Test Vector sha256 #3 */
#define TEST_VECTOR_SHA256_03_MSG \
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

#define TEST_VECTOR_SHA256_03_RES \
        "\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39" \
        "\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1"

/* Test Vector sha256 #4 */
#define TEST_VECTOR_SHA256_04_MSG \
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno" \
        "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"

#define TEST_VECTOR_SHA256_04_RES \
        "\xcf\x5b\x16\xa7\x78\xaf\x83\x80\x03\x6c\xe5\x9e\x7b\x04\x92\x37" \
        "\x0b\x24\x9b\x11\xe8\xf0\x7a\x51\xaf\xac\x45\x03\x7a\xfe\xe9\xd1"

#define TEST_VECTOR_SHA256(n) \
        { TEST_VECTOR_SHA256_ ## n ## _MSG, \
          TEST_VECTOR_SHA256_ ## n ## _RES, \
          sizeof(TEST_VECTOR_SHA256_ ## n ## _MSG) - 1 }

struct {
        const unsigned char *msg, *res;
        const size_t msg_length;
} sha256_tvectors[] = {
        TEST_VECTOR_SHA256(01),
        TEST_VECTOR_SHA256(02),
        TEST_VECTOR_SHA256(03),
        TEST_VECTOR_SHA256(04),
};

int crypto_sha256_testcnt(void)
{
	return sizeof(sha256_tvectors)/sizeof(sha256_tvectors[0]);
}

int crypto_sha256_test(int index)
{
	uint8_t res[32];
	uint8_t *msg = (uint8_t *)&sha256_tvectors[index].msg[0];
	uint8_t *msgres = (uint8_t *)&sha256_tvectors[index].res[0];
	size_t msglen = sha256_tvectors[index].msg_length;

	crypto_sha256(res, msg, msglen);
	return compare(res, msgres, CRYPTO_SHA256_BLOCKSIZE);
}

/* Test Vector #1 */
#define TEST_VECTOR_HMAC_SHA256_01_KEY \
        "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0"

#define TEST_VECTOR_HMAC_SHA256_01_MSG \
        "\x48\x69\x20\x54\x68\x65\x72\x65"

#define TEST_VECTOR_HMAC_SHA256_01_MAC \
        "\xe4\x84\x11\x26\x27\x15\xc8\x37\x0c\xd5\xe7\xbf\x8e\x82\xbe\xf5" \
        "\x3b\xd5\x37\x12\xd0\x07\xf3\x42\x93\x51\x84\x3b\x77\xc7\xbb\x9b"

/* Test Vector #2 */
#define TEST_VECTOR_HMAC_SHA256_02_KEY \
        "\x4a\x65\x66\x65"

#define TEST_VECTOR_HMAC_SHA256_02_MSG \
        "\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20" \
        "\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f"

#define TEST_VECTOR_HMAC_SHA256_02_MAC \
        "\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7" \
        "\x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43"

/* Test Vector #3 */
#define TEST_VECTOR_HMAC_SHA256_03_KEY \
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
        "\xaa\xaa\xaa\xaa"

#define TEST_VECTOR_HMAC_SHA256_03_MSG \
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd" \
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd" \
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd" \
        "\xdd\xdd"

#define TEST_VECTOR_HMAC_SHA256_03_MAC \
        "\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7" \
        "\x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe"


#define TEST_VECTOR_HMAC_SHA256(n) \
        { TEST_VECTOR_HMAC_SHA256_ ## n ## _KEY, \
          TEST_VECTOR_HMAC_SHA256_ ## n ## _MSG, \
          TEST_VECTOR_HMAC_SHA256_ ## n ## _MAC, \
          sizeof(TEST_VECTOR_HMAC_SHA256_ ## n ## _KEY) - 1, \
          sizeof(TEST_VECTOR_HMAC_SHA256_ ## n ## _MSG) - 1 }

struct {
        const unsigned char *key, *msg, *mac;
        const size_t key_length;
        const size_t msg_length;
} hmac_sha256_tvectors[] = {
        TEST_VECTOR_HMAC_SHA256(01),
        TEST_VECTOR_HMAC_SHA256(02),
        TEST_VECTOR_HMAC_SHA256(03),
};

int crypto_hmac_sha256_testcnt(void)
{
	return sizeof(hmac_sha256_tvectors)/sizeof(hmac_sha256_tvectors[0]);
}

int crypto_hmac_sha256_test(int index)
{
	uint8_t mac[32];
	uint8_t *key = (uint8_t *)&hmac_sha256_tvectors[index].key[0];
	uint8_t *msg = (uint8_t *)&hmac_sha256_tvectors[index].msg[0];
	uint8_t *msgmac = (uint8_t *)&hmac_sha256_tvectors[index].mac[0];
        size_t keylen = hmac_sha256_tvectors[index].key_length;
	size_t msglen = hmac_sha256_tvectors[index].msg_length;

	crypto_hmac_sha256(mac, key, keylen, msg, msglen);
	return compare(mac, msgmac, CRYPTO_SHA256_BLOCKSIZE);
}

#define TEST_VECTOR_HKDF_SHA256_01_MASTER \
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b" \
        "\x0b\x0b\x0b\x0b\x0b\x0b"

#define TEST_VECTOR_HKDF_SHA256_01_SALT \
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"

#define TEST_VECTOR_HKDF_SHA256_01_CONTEXT \
        "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9"

#define TEST_VECTOR_HKDF_SHA256_01_KEY \
        "\x3c\xb2\x5f\x25\xfa\xac\xd5\x7a\x90\x43\x4f\x64\xd0\x36\x2f\x2a" \
        "\x2d\x2d\x0a\x90\xcf\x1a\x5a\x4c\x5d\xb0\x2d\x56\xec\xc4\xc5\xbf" \
        "\x34\x00\x72\x08\xd5\xb8\x87\x18\x58\x65"

#define TEST_VECTOR_HKDF_SHA256_02_MASTER \
        "\x9b\xe5\xbf\xfb\x18\x70\xad\x77\x28\xed\xbe\x81\x6f\x87\x41\x92"

#define TEST_VECTOR_HKDF_SHA256_02_SALT \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_HKDF_SHA256_02_CONTEXT \
        "\x63\x6f\x6e\x74\x65\x78\x74"

#define TEST_VECTOR_HKDF_SHA256_02_KEY \
        "\x84\xdf\x2a\xe9\x5a\xaa\x1a\x32\x03\xc0\xf1\x67\x70\xd6\x3f\xc4" \
        "\xc2\xcd\xa1\xe1\x3b\x1d\x68\x99\x33\x69\xf4\xe1\xf9\x18\x35\x5d"

#define TEST_VECTOR_HKDF_SHA256_03_MASTER \
        "\x3f\x64\xc1\xac\xbc\x9d\x2a\x2c\x0f\x9c\xbf\xc7\xc9\x48\x33\x29"

#define TEST_VECTOR_HKDF_SHA256_03_SALT \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_HKDF_SHA256_03_CONTEXT \
        "\x63\x6f\x6e\x74\x65\x78\x74"

#define TEST_VECTOR_HKDF_SHA256_03_KEY \
        "\xb8\xd6\xde\x42\xc0\x03\x41\x53\x05\x2e\xb4\x47\x6b\xd7\x0a\xba" \
        "\x4d\xfe\x0f\x77\x72\x49\x68\x87\xb1\x30\x84\x89\xc6\x7d\xea\xbb" \
        "\x15\x0f\xc2\x7e\x3a\x32\xa4\x94\xb5\x66\x99\xc2\x0a\xbb\x2e\xad"

#define TEST_VECTOR_HKDF_SHA256(n) \
        { TEST_VECTOR_HKDF_SHA256_ ## n ## _MASTER, \
          TEST_VECTOR_HKDF_SHA256_ ## n ## _SALT, \
          TEST_VECTOR_HKDF_SHA256_ ## n ## _CONTEXT, \
          TEST_VECTOR_HKDF_SHA256_ ## n ## _KEY, \
          sizeof(TEST_VECTOR_HKDF_SHA256_ ## n ## _MASTER) - 1, \
          sizeof(TEST_VECTOR_HKDF_SHA256_ ## n ## _SALT) - 1, \
          sizeof(TEST_VECTOR_HKDF_SHA256_ ## n ## _CONTEXT) - 1, \
          sizeof(TEST_VECTOR_HKDF_SHA256_ ## n ## _KEY) - 1 }

struct {
        const unsigned char *master, *salt, *context, *key;
        const size_t master_length;
        const size_t salt_length;
        const size_t context_length;
        const size_t key_length;
} hkdf_sha256_tvectors[] = {
        TEST_VECTOR_HKDF_SHA256(01),
        TEST_VECTOR_HKDF_SHA256(02),
        TEST_VECTOR_HKDF_SHA256(03),
};

int crypto_hkdf_sha256_testcnt(void)
{
	return sizeof(hkdf_sha256_tvectors)/sizeof(hkdf_sha256_tvectors[0]);
}

int crypto_hkdf_sha256_test(int index)
{
	uint8_t *master = (uint8_t *)&hkdf_sha256_tvectors[index].master[0];
	uint8_t *salt = (uint8_t *)&hkdf_sha256_tvectors[index].salt[0];
	uint8_t *context = (uint8_t *)&hkdf_sha256_tvectors[index].context[0];
        uint8_t *key = (uint8_t *)&hkdf_sha256_tvectors[index].key[0];
        size_t masterlen = hkdf_sha256_tvectors[index].master_length;
	size_t saltlen = hkdf_sha256_tvectors[index].salt_length;
        size_t contextlen = hkdf_sha256_tvectors[index].context_length;
        size_t keylen = hkdf_sha256_tvectors[index].key_length;

        uint8_t hkdf[keylen];

        crypto_hkdf_sha256(hkdf, salt, saltlen, master, masterlen, context,
                           contextlen, keylen);

	return compare(hkdf, key, keylen);
}