/*
 * chacha20poly1305 tests
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mincrypt/crypto_chacha20poly1305.h"
#include "mincrypt_test/crypto_chacha20poly1305_tvectors.h"

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

/* Test Vector #1 */
#define TEST_VECTOR_CHACHA20_01_KEY \
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" \
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

#define TEST_VECTOR_CHACHA20_01_NONCE \
        "\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00"

#define TEST_VECTOR_CHACHA20_01_MSG \
        "Ladies and Gentlemen of the class of '99: If I could offer you " \
        "only one tip for the future, sunscreen would be it."

#define TEST_VECTOR_CHACHA20_01_RES \
        "\x6e\x2e\x35\x9a\x25\x68\xf9\x80\x41\xba\x07\x28\xdd\x0d\x69\x81" \
        "\xe9\x7e\x7a\xec\x1d\x43\x60\xc2\x0a\x27\xaf\xcc\xfd\x9f\xae\x0b" \
        "\xf9\x1b\x65\xc5\x52\x47\x33\xab\x8f\x59\x3d\xab\xcd\x62\xb3\x57" \
        "\x16\x39\xd6\x24\xe6\x51\x52\xab\x8f\x53\x0c\x35\x9f\x08\x61\xd8" \
        "\x07\xca\x0d\xbf\x50\x0d\x6a\x61\x56\xa3\x8e\x08\x8a\x22\xb6\x5e" \
        "\x52\xbc\x51\x4d\x16\xcc\xf8\x06\x81\x8c\xe9\x1a\xb7\x79\x37\x36" \
        "\x5a\xf9\x0b\xbf\x74\xa3\x5b\xe6\xb4\x0b\x8e\xed\xf2\x78\x5e\x42" \
        "\x87\x4d"

#define TEST_VECTOR_CHACHA20_01_IC 1

#define TEST_VECTOR_CHACHA20(n) \
        { TEST_VECTOR_CHACHA20_ ## n ## _KEY, \
          TEST_VECTOR_CHACHA20_ ## n ## _NONCE, \
          TEST_VECTOR_CHACHA20_ ## n ## _MSG, \
          TEST_VECTOR_CHACHA20_ ## n ## _RES, \
          sizeof(TEST_VECTOR_CHACHA20_ ## n ## _MSG) - 1, \
          TEST_VECTOR_CHACHA20_ ## n ## _IC }

struct {
        const unsigned char *key, *nonce, *msg, *res;
        const size_t msg_length;
        const uint32_t ic;
} chacha20_tvectors[] = {
        TEST_VECTOR_CHACHA20(01),
};

int crypto_chacha20_testcnt(void)
{
	return sizeof(chacha20_tvectors)/sizeof(chacha20_tvectors[0]);
}

int crypto_chacha20_test(int index)
{
	crypto_chacha20_ietf_in in;
	uint8_t *key = (uint8_t *)&chacha20_tvectors[index].key[0];
	uint8_t *nonce = (uint8_t *)&chacha20_tvectors[index].nonce[0];
	uint8_t *msg = (uint8_t *)&chacha20_tvectors[index].msg[0];
	uint8_t *res = (uint8_t *)&chacha20_tvectors[index].res[0];
	size_t msglen = chacha20_tvectors[index].msg_length;
	uint32_t ic = chacha20_tvectors[index].ic;
	uint8_t c[msglen];

	memcpy(&in.key, key, sizeof(in.key));
	memcpy(&in.nonce, nonce, sizeof(in.nonce));
	in.ic = ic;

	chacha20_ietf_xor(c, msg, msglen, &in);
	return compare(c, res, msglen);
}

/* the following test vectors come from Section A.3 of RFC 7539:
   "ChaCha20 and Poly1305 for IETF Protocols" by Y. Nir and
   A. Langley. */

/* Test Vector #1 */
#define TEST_VECTOR_POLY1305_01_KEY \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_POLY1305_01_MSG \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_POLY1305_01_MAC \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

/* Test Vector #2 */
#define TEST_VECTOR_POLY1305_02_KEY \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x36\xe5\xf6\xb5\xc5\xe0\x60\x70\xf0\xef\xca\x96\x22\x7a\x86\x3e"

#define TEST_VECTOR_POLY1305_02_MSG \
        "\x41\x6e\x79\x20\x73\x75\x62\x6d\x69\x73\x73\x69\x6f\x6e\x20\x74" \
        "\x6f\x20\x74\x68\x65\x20\x49\x45\x54\x46\x20\x69\x6e\x74\x65\x6e" \
        "\x64\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x43\x6f\x6e\x74\x72" \
        "\x69\x62\x75\x74\x6f\x72\x20\x66\x6f\x72\x20\x70\x75\x62\x6c\x69" \
        "\x63\x61\x74\x69\x6f\x6e\x20\x61\x73\x20\x61\x6c\x6c\x20\x6f\x72" \
        "\x20\x70\x61\x72\x74\x20\x6f\x66\x20\x61\x6e\x20\x49\x45\x54\x46" \
        "\x20\x49\x6e\x74\x65\x72\x6e\x65\x74\x2d\x44\x72\x61\x66\x74\x20" \
        "\x6f\x72\x20\x52\x46\x43\x20\x61\x6e\x64\x20\x61\x6e\x79\x20\x73" \
        "\x74\x61\x74\x65\x6d\x65\x6e\x74\x20\x6d\x61\x64\x65\x20\x77\x69" \
        "\x74\x68\x69\x6e\x20\x74\x68\x65\x20\x63\x6f\x6e\x74\x65\x78\x74" \
        "\x20\x6f\x66\x20\x61\x6e\x20\x49\x45\x54\x46\x20\x61\x63\x74\x69" \
        "\x76\x69\x74\x79\x20\x69\x73\x20\x63\x6f\x6e\x73\x69\x64\x65\x72" \
        "\x65\x64\x20\x61\x6e\x20\x22\x49\x45\x54\x46\x20\x43\x6f\x6e\x74" \
        "\x72\x69\x62\x75\x74\x69\x6f\x6e\x22\x2e\x20\x53\x75\x63\x68\x20" \
        "\x73\x74\x61\x74\x65\x6d\x65\x6e\x74\x73\x20\x69\x6e\x63\x6c\x75" \
        "\x64\x65\x20\x6f\x72\x61\x6c\x20\x73\x74\x61\x74\x65\x6d\x65\x6e" \
        "\x74\x73\x20\x69\x6e\x20\x49\x45\x54\x46\x20\x73\x65\x73\x73\x69" \
        "\x6f\x6e\x73\x2c\x20\x61\x73\x20\x77\x65\x6c\x6c\x20\x61\x73\x20" \
        "\x77\x72\x69\x74\x74\x65\x6e\x20\x61\x6e\x64\x20\x65\x6c\x65\x63" \
        "\x74\x72\x6f\x6e\x69\x63\x20\x63\x6f\x6d\x6d\x75\x6e\x69\x63\x61" \
        "\x74\x69\x6f\x6e\x73\x20\x6d\x61\x64\x65\x20\x61\x74\x20\x61\x6e" \
        "\x79\x20\x74\x69\x6d\x65\x20\x6f\x72\x20\x70\x6c\x61\x63\x65\x2c" \
        "\x20\x77\x68\x69\x63\x68\x20\x61\x72\x65\x20\x61\x64\x64\x72\x65" \
        "\x73\x73\x65\x64\x20\x74\x6f"

#define TEST_VECTOR_POLY1305_02_MAC \
        "\x36\xe5\xf6\xb5\xc5\xe0\x60\x70\xf0\xef\xca\x96\x22\x7a\x86\x3e"

/* Test Vector #3 */
#define TEST_VECTOR_POLY1305_03_KEY \
        "\x36\xe5\xf6\xb5\xc5\xe0\x60\x70\xf0\xef\xca\x96\x22\x7a\x86\x3e" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_POLY1305_03_MSG \
        "\x41\x6e\x79\x20\x73\x75\x62\x6d\x69\x73\x73\x69\x6f\x6e\x20\x74" \
        "\x6f\x20\x74\x68\x65\x20\x49\x45\x54\x46\x20\x69\x6e\x74\x65\x6e" \
        "\x64\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x43\x6f\x6e\x74\x72" \
        "\x69\x62\x75\x74\x6f\x72\x20\x66\x6f\x72\x20\x70\x75\x62\x6c\x69" \
        "\x63\x61\x74\x69\x6f\x6e\x20\x61\x73\x20\x61\x6c\x6c\x20\x6f\x72" \
        "\x20\x70\x61\x72\x74\x20\x6f\x66\x20\x61\x6e\x20\x49\x45\x54\x46" \
        "\x20\x49\x6e\x74\x65\x72\x6e\x65\x74\x2d\x44\x72\x61\x66\x74\x20" \
        "\x6f\x72\x20\x52\x46\x43\x20\x61\x6e\x64\x20\x61\x6e\x79\x20\x73" \
        "\x74\x61\x74\x65\x6d\x65\x6e\x74\x20\x6d\x61\x64\x65\x20\x77\x69" \
        "\x74\x68\x69\x6e\x20\x74\x68\x65\x20\x63\x6f\x6e\x74\x65\x78\x74" \
        "\x20\x6f\x66\x20\x61\x6e\x20\x49\x45\x54\x46\x20\x61\x63\x74\x69" \
        "\x76\x69\x74\x79\x20\x69\x73\x20\x63\x6f\x6e\x73\x69\x64\x65\x72" \
        "\x65\x64\x20\x61\x6e\x20\x22\x49\x45\x54\x46\x20\x43\x6f\x6e\x74" \
        "\x72\x69\x62\x75\x74\x69\x6f\x6e\x22\x2e\x20\x53\x75\x63\x68\x20" \
        "\x73\x74\x61\x74\x65\x6d\x65\x6e\x74\x73\x20\x69\x6e\x63\x6c\x75" \
        "\x64\x65\x20\x6f\x72\x61\x6c\x20\x73\x74\x61\x74\x65\x6d\x65\x6e" \
        "\x74\x73\x20\x69\x6e\x20\x49\x45\x54\x46\x20\x73\x65\x73\x73\x69" \
        "\x6f\x6e\x73\x2c\x20\x61\x73\x20\x77\x65\x6c\x6c\x20\x61\x73\x20" \
        "\x77\x72\x69\x74\x74\x65\x6e\x20\x61\x6e\x64\x20\x65\x6c\x65\x63" \
        "\x74\x72\x6f\x6e\x69\x63\x20\x63\x6f\x6d\x6d\x75\x6e\x69\x63\x61" \
        "\x74\x69\x6f\x6e\x73\x20\x6d\x61\x64\x65\x20\x61\x74\x20\x61\x6e" \
        "\x79\x20\x74\x69\x6d\x65\x20\x6f\x72\x20\x70\x6c\x61\x63\x65\x2c" \
        "\x20\x77\x68\x69\x63\x68\x20\x61\x72\x65\x20\x61\x64\x64\x72\x65" \
        "\x73\x73\x65\x64\x20\x74\x6f"

#define TEST_VECTOR_POLY1305_03_MAC \
        "\xf3\x47\x7e\x7c\xd9\x54\x17\xaf\x89\xa6\xb8\x79\x4c\x31\x0c\xf0"

/* Test Vector #4 */
#define TEST_VECTOR_POLY1305_04_KEY \
        "\x1c\x92\x40\xa5\xeb\x55\xd3\x8a\xf3\x33\x88\x86\x04\xf6\xb5\xf0" \
        "\x47\x39\x17\xc1\x40\x2b\x80\x09\x9d\xca\x5c\xbc\x20\x70\x75\xc0"

#define TEST_VECTOR_POLY1305_04_MSG \
        "\x27\x54\x77\x61\x73\x20\x62\x72\x69\x6c\x6c\x69\x67\x2c\x20\x61" \
        "\x6e\x64\x20\x74\x68\x65\x20\x73\x6c\x69\x74\x68\x79\x20\x74\x6f" \
        "\x76\x65\x73\x0a\x44\x69\x64\x20\x67\x79\x72\x65\x20\x61\x6e\x64" \
        "\x20\x67\x69\x6d\x62\x6c\x65\x20\x69\x6e\x20\x74\x68\x65\x20\x77" \
        "\x61\x62\x65\x3a\x0a\x41\x6c\x6c\x20\x6d\x69\x6d\x73\x79\x20\x77" \
        "\x65\x72\x65\x20\x74\x68\x65\x20\x62\x6f\x72\x6f\x67\x6f\x76\x65" \
        "\x73\x2c\x0a\x41\x6e\x64\x20\x74\x68\x65\x20\x6d\x6f\x6d\x65\x20" \
        "\x72\x61\x74\x68\x73\x20\x6f\x75\x74\x67\x72\x61\x62\x65\x2e"

#define TEST_VECTOR_POLY1305_04_MAC \
        "\x45\x41\x66\x9a\x7e\xaa\xee\x61\xe7\x08\xdc\x7c\xbc\xc5\xeb\x62"

/* Test Vector #5 */
#define TEST_VECTOR_POLY1305_05_KEY \
        "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_POLY1305_05_MSG \
        "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"

#define TEST_VECTOR_POLY1305_05_MAC \
        "\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

/* Test Vector #6 */
#define TEST_VECTOR_POLY1305_06_KEY \
        "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"

#define TEST_VECTOR_POLY1305_06_MSG \
        "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_POLY1305_06_MAC \
        "\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

/* Test Vector #7 */
#define TEST_VECTOR_POLY1305_07_KEY \
        "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_POLY1305_07_MSG \
        "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
        "\xF0\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
        "\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_POLY1305_07_MAC \
        "\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

/* Test Vector #8 */
#define TEST_VECTOR_POLY1305_08_KEY \
        "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_POLY1305_08_MSG \
        "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
        "\xFB\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE" \
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"

#define TEST_VECTOR_POLY1305_08_MAC \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

/* Test Vector #9 */
#define TEST_VECTOR_POLY1305_09_KEY \
        "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_POLY1305_09_MSG \
        "\xFD\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"

#define TEST_VECTOR_POLY1305_09_MAC \
        "\xFA\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"

/* Test Vector #10 */
#define TEST_VECTOR_POLY1305_10_KEY \
        "\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_POLY1305_10_MSG \
        "\xE3\x35\x94\xD7\x50\x5E\x43\xB9\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x33\x94\xD7\x50\x5E\x43\x79\xCD\x01\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_POLY1305_10_MAC \
        "\x14\x00\x00\x00\x00\x00\x00\x00\x55\x00\x00\x00\x00\x00\x00\x00"

/* Test Vector #11 */
#define TEST_VECTOR_POLY1305_11_KEY \
        "\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_POLY1305_11_MSG \
        "\xE3\x35\x94\xD7\x50\x5E\x43\xB9\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x33\x94\xD7\x50\x5E\x43\x79\xCD\x01\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_POLY1305_11_MAC \
        "\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define TEST_VECTOR_POLY1305(n) \
        { TEST_VECTOR_POLY1305_ ## n ## _KEY, \
          TEST_VECTOR_POLY1305_ ## n ## _MSG, \
          TEST_VECTOR_POLY1305_ ## n ## _MAC, \
          sizeof(TEST_VECTOR_POLY1305_ ## n ## _MSG)-1 }

struct {
        const unsigned char *key, *msg, *mac;
        const size_t msg_length;
} poly1305_tvectors[] = {
        TEST_VECTOR_POLY1305(01),
        TEST_VECTOR_POLY1305(02),
        TEST_VECTOR_POLY1305(03),
        TEST_VECTOR_POLY1305(04),
        TEST_VECTOR_POLY1305(05),
        TEST_VECTOR_POLY1305(06),
        TEST_VECTOR_POLY1305(07),
        TEST_VECTOR_POLY1305(08),
        TEST_VECTOR_POLY1305(09),
        TEST_VECTOR_POLY1305(10),
        TEST_VECTOR_POLY1305(11),
};

int crypto_poly1305_testcnt(void)
{
	return sizeof(poly1305_tvectors)/sizeof(poly1305_tvectors[0]);
}

int crypto_poly1305_test(int index)
{
	uint8_t mac[32];
	uint8_t *key = (uint8_t *)&poly1305_tvectors[index].key[0];
	uint8_t *msg = (uint8_t *)&poly1305_tvectors[index].msg[0];
	uint8_t *msgmac = (uint8_t *)&poly1305_tvectors[index].mac[0];
	size_t msglen = poly1305_tvectors[index].msg_length;

	crypto_poly1305(mac, key, msg, msglen);
	return compare(mac, msgmac, CRYPTO_POLY1305_BLOCKSIZE);
}