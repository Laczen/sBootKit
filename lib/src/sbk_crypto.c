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
#include "sbk/sbk_log.h"
#ifdef CONFIG_SBK_MINCRYPT
#include "mincrypt/crypto_sha256.h"
#include "mincrypt/crypto_chacha20poly1305.h"
#endif
#ifdef CONFIG_SBK_P256M
#include "p256-m.h"
#endif

void sbk_crypto_cwipe(void *secret, size_t size)
{
	volatile uint8_t *v_secret = (uint8_t *)secret;
	for (size_t i = 0; i < size; i++) {
		v_secret[i] = 0U;
	}
}

int sbk_crypto_compare(const void *s1, const void *s2, size_t len)
{
	uint8_t *s1_8 = (uint8_t *)s1;
	uint8_t *s2_8 = (uint8_t *)s2;
	int rc = 0;

	for (size_t i = 0; i < len; i++) {
		rc |= s1_8[i] ^ s2_8[i];
	}

	return rc;
}

#ifdef CONFIG_SBK_MINCRYPT
void sbk_crypto_kxch(const struct sbk_crypto_kxch_ctx *ctx, void *keymaterial,
		     size_t keymaterial_size)
{
	uint8_t prk[crypto_hkdf_sha256_prk_size()];

	crypto_hkdf_sha256_extract(prk, ctx->salt, ctx->salt_size, ctx->pkey,
				   ctx->pkey_size);
	crypto_hkdf_sha256_expand(keymaterial, prk, ctx->context,
				  ctx->context_size, keymaterial_size);

	sbk_crypto_cwipe(prk, sizeof(prk));
}
#else
void sbk_crypto_kxch(const struct sbk_crypto_kxch_ctx *ctx, void *keymaterial,
		     size_t keymaterial_size)
{
}
#endif

#ifdef CONFIG_SBK_MINCRYPT
static int sbk_crypto_hmac_calc(void *hmac, const void *key, size_t key_size,
				const struct sbk_crypto_read_ctx *read_ctx,
				size_t msg_len)
{
	uint8_t state[crypto_hmac_sha256_state_size()];
	uint8_t buf[crypto_hmac_sha256_block_size()];
	uint32_t off = 0U;
	int rc = 0;

	crypto_hmac_sha256_init(state, key, key_size);
	while (msg_len != 0U) {
		size_t rdlen = SBK_MIN(msg_len, sizeof(buf));
		rc = read_ctx->read(read_ctx->ctx, off, buf, rdlen);
		if (rc != 0) {
			goto end;
		}

		crypto_hmac_sha256_update(state, buf, rdlen);
		msg_len -= rdlen;
		off += rdlen;
	}

	crypto_hmac_sha256_final(hmac, state);
end:
	sbk_crypto_cwipe(state, sizeof(state));
	sbk_crypto_cwipe(buf, sizeof(buf));
	return rc;
}
#else
static int sbk_crypto_hmac_calc(void *hmac, const void *key, size_t key_size,
				const struct sbk_crypto_read_ctx *read_ctx,
				size_t msg_len)
{
	return -SBK_EC_EFAULT;
}
#endif

#ifdef CONFIG_SBK_MINCRYPT
int sbk_crypto_hmac_vrfy(const struct sbk_crypto_hmac_ctx *ctx,
			 const struct sbk_crypto_read_ctx *read_ctx,
			 size_t msg_len)
{
	if (ctx->hmac_size > crypto_hmac_sha256_block_size()) {
		return -SBK_EC_EFAULT;
	}

	uint8_t hmac[crypto_hmac_sha256_block_size()];
	int rc;

	rc = sbk_crypto_hmac_calc(hmac, ctx->key, ctx->key_size, read_ctx,
				  msg_len);
	if (rc != 0) {
		goto end;
	}

	rc = sbk_crypto_compare(hmac, ctx->hmac, ctx->hmac_size);
end:
	sbk_crypto_cwipe(hmac, sizeof(hmac));
	return rc;
}
#else
int sbk_crypto_hmac_vrfy(const struct sbk_crypto_hmac_ctx *ctx,
			 const struct sbk_crypto_read_ctx *read_ctx,
			 size_t msg_len)
{
	return -SBK_EC_EFAULT;
}
#endif

#ifdef CONFIG_SBK_MINCRYPT
static int sbk_crypto_hash_calc(void *hash,
				const struct sbk_crypto_read_ctx *read_ctx,
				size_t msg_len)
{
	uint8_t state[crypto_sha256_state_size()];
	uint8_t buf[crypto_sha256_block_size()];
	uint32_t off = 0U;
	int rc = 0;

	crypto_sha256_init(state);
	while (msg_len != 0U) {
		size_t rdlen = SBK_MIN(msg_len, sizeof(buf));
		rc = read_ctx->read(read_ctx->ctx, off, buf, rdlen);
		if (rc != 0) {
			goto end;
		}

		crypto_sha256_update(state, buf, rdlen);
		msg_len -= rdlen;
		off += rdlen;
	}

	crypto_sha256_final(hash, state);
end:
	sbk_crypto_cwipe(state, sizeof(state));
	sbk_crypto_cwipe(buf, sizeof(buf));
	return rc;
}
#else
static int sbk_crypto_hash_calc(void *hash,
				const struct sbk_crypto_read_ctx *read_ctx,
				size_t msg_len)
{
	return 0;
}
#endif

#ifdef CONFIG_SBK_MINCRYPT
int sbk_crypto_hash_vrfy(const struct sbk_crypto_hash_ctx *ctx,
			 const struct sbk_crypto_read_ctx *read_ctx,
			 size_t msg_len)
{
	if (ctx->hash_size > crypto_sha256_block_size()) {
		return -SBK_EC_EFAULT;
	}

	uint8_t hash[crypto_sha256_block_size()];
	int rc;

	rc = sbk_crypto_hash_calc(hash, read_ctx, msg_len);
	if (rc != 0) {
		goto end;
	}

	rc = sbk_crypto_compare(hash, ctx->hash, ctx->hash_size);
end:
	sbk_crypto_cwipe(hash, sizeof(hash));
	return rc;
}
#else
int sbk_crypto_hash_vrfy(const struct sbk_crypto_hash_ctx *ctx,
			 const struct sbk_crypto_read_ctx *read_ctx,
			 size_t msg_len)
{
	return -SBK_EC_EFAULT;
}
#endif

#if defined(CONFIG_SBK_MINCRYPT) && defined(CONFIG_SBK_P256M)
int sbk_crypto_sigp256_vrfy(const struct sbk_crypto_sigp256_ctx *ctx,
			    const struct sbk_crypto_read_ctx *read_ctx,
			    size_t msg_len)
{
	if ((ctx->pubkey_size != 64) || (ctx->signature_size != 64)) {
		return -SBK_EC_EFAULT;
	}

	uint8_t hash[crypto_sha256_block_size()];
	int rc;

	rc = sbk_crypto_hash_calc(hash, read_ctx, msg_len);
	if (rc != 0) {
		goto end;
	}

	rc = p256_ecdsa_verify(ctx->signature, ctx->pubkey, hash, sizeof(hash));
	if (rc != P256_SUCCESS) {
		rc = -SBK_EC_EFAULT;
	}

end:
	sbk_crypto_cwipe(hash, sizeof(hash));
	return rc;
}
#else
int sbk_crypto_sigp256_vrfy(const struct sbk_crypto_sigp256_ctx *ctx,
			    const struct sbk_crypto_read_ctx *read_ctx,
			    size_t msg_len)
{
	return -SBK_EC_EFAULT;
}
#endif

#ifdef CONFIG_SBK_MINCRYPT
size_t sbk_crypto_ciphered_read_km_size(void)
{
	return crypto_chacha20_ietf_key_size() +
	       crypto_chacha20_ietf_nonce_size();
}
#else
size_t sbk_crypto_ciphered_read_km_size(void)
{
	return 0U;
}
#endif

#ifdef CONFIG_SBK_MINCRYPT
int sbk_crypto_ciphered_read(const struct sbk_crypto_ciphered_read_ctx *ctx,
			     uint32_t off, void *data, size_t len)
{
	const struct sbk_crypto_read_ctx *rctx = ctx->read_ctx;
	const size_t cbsize = crypto_chacha20_ietf_block_size();
	const size_t cssize = crypto_chacha20_ietf_state_size();
	const uint8_t *key = ctx->key;
	const uint8_t *nonce = key + crypto_chacha20_ietf_key_size();
	uint8_t dbuf[cbsize], cbuf[cbsize], est[cssize];
	uint8_t *data8 = (uint8_t *)data;
	int rc;

	while (len != 0U) {
		uint32_t bcnt = off / cbsize;
		uint32_t boff = bcnt * cbsize;
		uint32_t rdsize = SBK_MIN(cbsize, off + len - boff);

		memset(dbuf, 0, cbsize);
		rc = rctx->read(rctx->ctx, boff, dbuf, rdsize);
		if (rc != 0) {
			break;
		}

		crypto_chacha20_ietf_init(est, key, nonce, bcnt);
		crypto_chacha20_ietf_xor(cbuf, dbuf, cbsize, est);
		sbk_crypto_cwipe(est, sizeof(est));

		while ((len != 0U) && ((off - boff) < cbsize)) {
			(*data8) = cbuf[off - boff];
			data8++;
			off++;
			len--;
		}

		sbk_crypto_cwipe(dbuf, sizeof(dbuf));
		sbk_crypto_cwipe(cbuf, sizeof(cbuf));
	}

	return rc;
}
#else
int sbk_crypto_ciphered_read(const struct sbk_crypto_ciphered_read_ctx *ctx,
			     uint32_t off, void *data, size_t len)
{
	return -SBK_EC_EFAULT;
}
#endif
