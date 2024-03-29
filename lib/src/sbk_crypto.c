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
void sbk_crypto_hkdf_sha256_kxch(const struct sbk_crypto_kxch_ctx *ctx,
				 void *keymaterial, size_t keymaterial_size)
{
	uint8_t prk[crypto_hkdf_sha256_prk_size()];

	crypto_hkdf_sha256_extract(prk, ctx->salt, ctx->salt_size, ctx->pkey,
				   ctx->pkey_size);
	crypto_hkdf_sha256_expand(keymaterial, prk, ctx->context,
				  ctx->context_size, keymaterial_size);

	sbk_crypto_cwipe(prk, sizeof(prk));
}
#else
void sbk_crypto_hkdf_sha256_kxch(const struct sbk_crypto_kxch_ctx *ctx,
				 void *keymaterial, size_t keymaterial_size)
{
}
#endif

#ifdef CONFIG_SBK_MINCRYPT
static int sbk_crypto_hmac_sha256(void *hmac,
				  const struct sbk_crypto_hmac_ctx *hmac_ctx,
				  const struct sbk_crypto_read_ctx *read_ctx,
				  size_t msg_len)
{
	const size_t chunksz = hmac_ctx->chunk_size;
	uint8_t state[crypto_hmac_sha256_state_size()];
	uint8_t buf[SBK_MAX(chunksz, crypto_hmac_sha256_block_size())];
	uint32_t off = 0U;
	int rc = 0;

	crypto_hmac_sha256_init(state, hmac_ctx->key, hmac_ctx->key_size);
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
static int sbk_crypto_hmac_sha256(void *hmac,
				  const struct sbk_crypto_hmac_ctx *hmac_ctx,
				  const struct sbk_crypto_read_ctx *read_ctx,
				  size_t msg_len)
{
	return -SBK_EC_EFAULT;
}
#endif

#ifdef CONFIG_SBK_MINCRYPT
int sbk_crypto_hmac_sha256_vrfy(const struct sbk_crypto_hmac_ctx *hmac_ctx,
			 	const struct sbk_crypto_read_ctx *read_ctx,
			 	size_t msg_len)
{
	if (hmac_ctx->hmac_size > crypto_hmac_sha256_block_size()) {
		return -SBK_EC_EFAULT;
	}

	uint8_t hmac[crypto_hmac_sha256_block_size()];
	int rc;

	rc = sbk_crypto_hmac_sha256(hmac, hmac_ctx, read_ctx, msg_len);
	if (rc != 0) {
		goto end;
	}

	rc = sbk_crypto_compare(hmac, hmac_ctx->hmac, hmac_ctx->hmac_size);
end:
	sbk_crypto_cwipe(hmac, sizeof(hmac));
	return rc;
}
#else
int sbk_crypto_hmac_sha256_vrfy(const struct sbk_crypto_hmac_ctx *hmac_ctx,
				const struct sbk_crypto_read_ctx *read_ctx,
				size_t msg_len)
{
	return -SBK_EC_EFAULT;
}
#endif

#ifdef CONFIG_SBK_MINCRYPT
static int sbk_crypto_sha256(void *sha256,
			     const struct sbk_crypto_sha_ctx *sha_ctx,
			     const struct sbk_crypto_read_ctx *read_ctx,
			     size_t msg_len)
{
	const size_t chunksz = sha_ctx->chunk_size;
	uint8_t state[crypto_sha256_state_size()];
	uint8_t buf[SBK_MAX(chunksz, crypto_sha256_block_size())];
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

	crypto_sha256_final(sha256, state);
end:
	sbk_crypto_cwipe(state, sizeof(state));
	sbk_crypto_cwipe(buf, sizeof(buf));
	return rc;
}
#else
static int sbk_crypto_sha256(void *sha256,
			     const struct sbk_crypto_sha_ctx *sha_ctx,
			     const struct sbk_crypto_read_ctx *read_ctx,
			     size_t msg_len)
{
	return 0;
}
#endif

#ifdef CONFIG_SBK_MINCRYPT
int sbk_crypto_sha256_vrfy(const struct sbk_crypto_sha_ctx *sha_ctx,
			   const struct sbk_crypto_read_ctx *read_ctx,
			   size_t msg_len)
{
	if (sha_ctx->sha_size > crypto_sha256_block_size()) {
		return -SBK_EC_EFAULT;
	}

	uint8_t sha256[crypto_sha256_block_size()];
	int rc;

	rc = sbk_crypto_sha256(sha256, sha_ctx, read_ctx, msg_len);
	if (rc != 0) {
		goto end;
	}

	rc = sbk_crypto_compare(sha256, sha_ctx->sha, sha_ctx->sha_size);
end:
	sbk_crypto_cwipe(sha256, sizeof(sha256));
	return rc;
}
#else
int sbk_crypto_sha256_vrfy(const struct sbk_crypto_sha_ctx *sha_ctx,
			   const struct sbk_crypto_read_ctx *read_ctx,
			   size_t msg_len)
{
	return -SBK_EC_EFAULT;
}
#endif

#if defined(CONFIG_SBK_MINCRYPT) && defined(CONFIG_SBK_P256M)
int sbk_crypto_sig_p256_vrfy(const struct sbk_crypto_sig_p256_ctx *sig_ctx,
			     const struct sbk_crypto_read_ctx *read_ctx,
			     size_t msg_len)
{
	if ((sig_ctx->pubkey_size != 64) || (sig_ctx->signature_size != 64)) {
		return -SBK_EC_EFAULT;
	}

	uint8_t sha256[crypto_sha256_block_size()];
	const struct sbk_crypto_sha_ctx sha_ctx = {
		.sha = NULL,
		.sha_size = crypto_sha256_block_size(),
		.chunk_size = crypto_sha256_block_size(),
	};
	int rc;

	rc = sbk_crypto_sha256(sha256, &sha_ctx, read_ctx, msg_len);
	if (rc != 0) {
		goto end;
	}

	rc = p256_ecdsa_verify(sig_ctx->signature, sig_ctx->pubkey, sha256,
			       sizeof(sha256));
	if (rc != P256_SUCCESS) {
		rc = -SBK_EC_EFAULT;
	}

end:
	sbk_crypto_cwipe(sha256, sizeof(sha256));
	return rc;
}
#else
int sbk_crypto_sig_p256_vrfy(const struct sbk_crypto_sig_p256_ctx *sig_ctx,
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

		while ((len != 0U) && ((off - boff) < rdsize)) {
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
