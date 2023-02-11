/*
 * For more information see crypto_poly1305.h
 *
 * poly1305 implementation using 32 bit * 32 bit = 64 bit multiplication and 64
 * bit addition.
 *
 * Modified from poly1305-donna-(32) to reduce code size. For the original code
 * see https://github.com/floodyberry/poly1305-donna.
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mincrypt/crypto_chacha20poly1305.h"

static void cwipe(void *secret, size_t size)
{
	volatile uint8_t *v_secret = (uint8_t *)secret;
	for (size_t i = 0; i < size; i++) {
                v_secret[i] = 0U;
        }
}

/* interpret four 8 bit unsigned integers as a 32 bit unsigned integer in little endian */
static uint32_t U8TO32(const uint8_t *p) {
	return	(((uint32_t)(p[0] & 0xff)      ) |
	         ((uint32_t)(p[1] & 0xff) <<  8) |
                 ((uint32_t)(p[2] & 0xff) << 16) |
                 ((uint32_t)(p[3] & 0xff) << 24));
}

/* store a 32 bit unsigned integer as four 8 bit unsigned integers in little endian */
static void U32TO8(uint8_t *p, uint32_t v) {
	p[0] = (v      ) & 0xff;
	p[1] = (v >>  8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}

/* chacha20 */
static uint32_t ROTL32(const uint32_t x, const int b)
{
        return (x << b) | (x >> (32 - b));
}

#define U32C(v) (v##U)
#define U32V(v) ((uint32_t)(v) &U32C(0xFFFFFFFF))
#define ROTATE(v, c) (ROTL32(v, c))
#define XOR(v, w) ((v) ^ (w))
#define PLUS(v, w) (U32V((v) + (w)))

#define QUARTERROUND(a, b, c, d) \
    a = PLUS(a, b);              \
    d = ROTATE(XOR(d, a), 16);   \
    c = PLUS(c, d);              \
    b = ROTATE(XOR(b, c), 12);   \
    a = PLUS(a, b);              \
    d = ROTATE(XOR(d, a), 8);    \
    c = PLUS(c, d);              \
    b = ROTATE(XOR(b, c), 7);

typedef struct {
    uint32_t input[16];
} crypto_chacha20_ctx;

static void chacha20_key_setup(crypto_chacha20_ctx *ctx, const uint8_t *k)
{
    ctx->input[0]  = U32C(0x61707865);
    ctx->input[1]  = U32C(0x3320646e);
    ctx->input[2]  = U32C(0x79622d32);
    ctx->input[3]  = U32C(0x6b206574);
    ctx->input[4]  = U8TO32(k + 0);
    ctx->input[5]  = U8TO32(k + 4);
    ctx->input[6]  = U8TO32(k + 8);
    ctx->input[7]  = U8TO32(k + 12);
    ctx->input[8]  = U8TO32(k + 16);
    ctx->input[9]  = U8TO32(k + 20);
    ctx->input[10] = U8TO32(k + 24);
    ctx->input[11] = U8TO32(k + 28);
}

static void chacha20_nonce_setup(crypto_chacha20_ctx *ctx, const uint8_t *nonce,
                                 const uint8_t *cnt)
{
    ctx->input[12] = cnt == NULL ? 0 : U8TO32(cnt + 0);
    ctx->input[13] = cnt == NULL ? 0 : U8TO32(cnt + 4);
    ctx->input[14] = U8TO32(nonce + 0);
    ctx->input[15] = U8TO32(nonce + 4);
}

static void chacha20_ietf_nonce_setup(crypto_chacha20_ctx *ctx,
                                      const uint8_t *nonce, const uint8_t *cnt)
{
    ctx->input[12] = cnt == NULL ? 0 : U8TO32(cnt);
    ctx->input[13] = U8TO32(nonce + 0);
    ctx->input[14] = U8TO32(nonce + 4);
    ctx->input[15] = U8TO32(nonce + 8);
}

static void chacha20_encrypt_bytes(crypto_chacha20_ctx *ctx, uint8_t *c,
				   const uint8_t *m, uint64_t bytes)
{
        uint32_t x[16];
        uint32_t j[16];
        uint8_t  *ctarget = NULL;
        uint8_t  tmp[64];
        unsigned int i;

        if (!bytes) {
                return; /* LCOV_EXCL_LINE */
        }

        memcpy(j, ctx->input, sizeof(j));
        for (;;) {
                if (bytes < 64) {
                        memset(tmp, 0, 64);
                        for (i = 0; i < bytes; ++i) {
                                tmp[i] = m[i];
                        }
                        m       = tmp;
                        ctarget = c;
                        c       = tmp;
                }

                memcpy(x, j, sizeof(j));
                for (i = 20; i > 0; i -= 2) {
                        QUARTERROUND(x[0], x[4], x[8], x[12])
                        QUARTERROUND(x[1], x[5], x[9], x[13])
                        QUARTERROUND(x[2], x[6], x[10], x[14])
                        QUARTERROUND(x[3], x[7], x[11], x[15])
                        QUARTERROUND(x[0], x[5], x[10], x[15])
                        QUARTERROUND(x[1], x[6], x[11], x[12])
                        QUARTERROUND(x[2], x[7], x[8], x[13])
                        QUARTERROUND(x[3], x[4], x[9], x[14])
                }

                for (i = 0; i < 16; i++) {
                        x[i] += j[i];
                        x[i] ^= U8TO32(m + 4 * i);
                }

                j[12]++;
                /* LCOV_EXCL_START */
                if (j[12] == 0) {
                        j[13]++;
                }
                /* LCOV_EXCL_STOP */
                for (i = 0; i < 16; ++i) {
                        U32TO8(c + 4 * i, x[i]);
                }

                if (bytes <= 64) {
                        if (bytes < 64) {
                                for (i = 0; i < (unsigned int) bytes; ++i) {
                                        ctarget[i] = c[i]; /* ctarget cannot be NULL */
                                }
                        }
                        ctx->input[12] = j[12];
                        ctx->input[13] = j[13];

                        return;
                }
                bytes -= 64;
                c += 64;
                m += 64;
        }
}

void chacha20_ref_xor(uint8_t *c, const uint8_t *m, uint64_t clen,
		      crypto_chacha20_ref_in *in)
{
        crypto_chacha20_ctx ctx;
	uint8_t ic_bytes[8];
        uint32_t ic_high;
        uint32_t ic_low;

        if (!clen) {
                return;
        }
	ic_high = U32V(in->ic >> 32);
        ic_low  = U32V(in->ic);
        U32TO8(&ic_bytes[0], ic_low);
        U32TO8(&ic_bytes[4], ic_high);

        chacha20_key_setup(&ctx, in->key);
        chacha20_nonce_setup(&ctx, in->nonce, ic_bytes);
	if (m == NULL) {
		memset(c, 0, clen);
        	chacha20_encrypt_bytes(&ctx, c, c, clen);
	} else {
		chacha20_encrypt_bytes(&ctx, c, m, clen);
	}

        cwipe(&ctx, sizeof(ctx));
}

void chacha20_ietf_xor(uint8_t *c, const uint8_t *m, uint32_t clen,
		       crypto_chacha20_ietf_in *in)
{
        crypto_chacha20_ctx ctx;
	uint8_t ic_bytes[4];

        if (!clen) {
                return;
        }

	U32TO8(ic_bytes, in->ic);

        chacha20_key_setup(&ctx, in->key);
        chacha20_ietf_nonce_setup(&ctx, in->nonce, ic_bytes);
	if (m == NULL) {
		memset(c, 0, clen);
        	chacha20_encrypt_bytes(&ctx, c, c, (uint64_t)clen);
	} else {
		chacha20_encrypt_bytes(&ctx, c, m, (uint64_t)clen);
	}

        cwipe(&ctx, sizeof(ctx));
}


/* poly1305 */
void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const uint8_t key[32])
{

	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	ctx->r[0] = (U8TO32(&key[ 0])     ) & 0x3ffffff;
	ctx->r[1] = (U8TO32(&key[ 3]) >> 2) & 0x3ffff03;
	ctx->r[2] = (U8TO32(&key[ 6]) >> 4) & 0x3ffc0ff;
	ctx->r[3] = (U8TO32(&key[ 9]) >> 6) & 0x3f03fff;
	ctx->r[4] = (U8TO32(&key[12]) >> 8) & 0x00fffff;

	/* h = 0 */
	for (size_t i = 0; i < 5; ++i) {
		ctx->h[i] = 0U;
	}

	/* save pad for later */
	for (size_t i = 0; i < 4; ++i) {
		ctx->pad[i] = U8TO32(&key[16 + 4 * i]);
	}

	ctx->bufpos = 0U;
}

static void poly1305_block(crypto_poly1305_ctx *ctx, uint32_t hibit)
{
	uint32_t h[5];
	uint32_t c = 0U;

	ctx->h[0] += (U8TO32(&ctx->buf[0])      ) & 0x3ffffff;
	ctx->h[1] += (U8TO32(&ctx->buf[3]) >>  2) & 0x3ffffff;
	ctx->h[2] += (U8TO32(&ctx->buf[6]) >>  4) & 0x3ffffff;
	ctx->h[3] += (U8TO32(&ctx->buf[9]) >>  6) & 0x3ffffff;
	ctx->h[4] += (U8TO32(&ctx->buf[12]) >> 8) | hibit;

	/* h *= r */
	for (size_t i = 0U; i < 5; ++i) {
		uint64_t d = c;
		for (size_t j = 0U; j < 5; j++) {
			if (j <= i) {
				d += (uint64_t)ctx->h[j] * ctx->r[i - j];
			} else {
				d += (uint64_t)ctx->h[j] * ctx->r[5 - (j - i)] * 5;
			}
		}
		c = (uint32_t)(d >> 26);
		h[i] = (uint32_t)d & 0x3ffffff;
	}

	h[0] += c * 5;
	h[1] += h[0] >> 26;
	h[0] &= 0x3ffffff;

	ctx->h[0] = h[0];
	ctx->h[1] = h[1];
	ctx->h[2] = h[2];
	ctx->h[3] = h[3];
	ctx->h[4] = h[4];
}

void crypto_poly1305_final(uint8_t mac[16], crypto_poly1305_ctx *ctx)
{
	const uint32_t hibit = 0U;
	uint32_t g[5];
	uint32_t c, s, mask;
	uint64_t f;

	/* process the remaining block */
	if (ctx->bufpos != 0U) {
		size_t i = ctx->bufpos;
		ctx->buf[i++] = 1;
		for (; i < CRYPTO_POLY1305_BLOCKSIZE; i++) {
			ctx->buf[i] = 0;
		}
		poly1305_block(ctx, hibit);
		ctx->bufpos = 0;
	}

	/* fully carry h */
	c = 0U;
	for (size_t i = 1; i < 5; i++) {
		ctx->h[i] += c;
		c = ctx->h[i] >> 26;
		ctx->h[i] &= 0x3ffffff;
	}

	ctx->h[0] += c * 5;
	ctx->h[1] += ctx->h[0] >> 26;
	ctx->h[0] &= 0x3ffffff;

	/* compute h + -p */
	c = 5;
	for (size_t i = 0; i < 4; ++i) {
		g[i] = ctx->h[i] + c;
		c = g[i] >> 26;
		g[i] &= 0x3ffffff;
	}
	g[4] = ctx->h[4] + c - (1UL << 26);

	/* select h if h < p, or h + -p if h >= p */
	mask = (g[4] >> ((sizeof(uint32_t) * 8) - 1)) - 1;

	/* h = h % (2^128) */
	f = 0U;
	s = 0U;
	for (size_t i = 0; i < 4; i++) {
		uint32_t h1, h2;

		h1 = (ctx->h[i] & ~mask) | (g[i] & mask);
		h2 = (ctx->h[i+1] & ~mask) | (g[i+1] & mask);
		f >>= 32;
		f += ((h1 >> s) | (h2 << (26 - s))) & 0xffffffff;
		f += ctx->pad[i];
		U32TO8(mac, (uint32_t)f);
		mac += 4;
		s += 6;
	}

	cwipe((void *)g, sizeof(g));
	cwipe((void *)ctx, sizeof(crypto_poly1305_ctx)); /* zero out the ctx */
}

void crypto_poly1305_update(crypto_poly1305_ctx *ctx, const uint8_t *msg,
			    size_t msglen)
{
	const uint32_t hibit = (1UL << 24);

	while (msglen--) {
 		ctx->buf[ctx->bufpos++] = *msg++;
 		if (ctx->bufpos == CRYPTO_POLY1305_BLOCKSIZE) {
 			poly1305_block(ctx, hibit);
 			ctx->bufpos = 0;
 		}
 	}
}

void crypto_poly1305(uint8_t mac[16], const uint8_t key[32], const uint8_t *msg,
		     size_t msglen)
{
	crypto_poly1305_ctx ctx;
	crypto_poly1305_init(&ctx, key);
	crypto_poly1305_update(&ctx, msg, msglen);
	crypto_poly1305_final(mac, &ctx);
}