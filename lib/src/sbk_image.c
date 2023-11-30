/*
 * Copyright (c) 2023 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stddef.h>
#include <string.h>
#include "sbk/sbk_util.h"
#include "sbk/sbk_crypto.h"
#include "sbk/sbk_slot.h"
#include "sbk/sbk_image.h"
#include "sbk/sbk_log.h"
#include "sbk/sbk_keys.h"

struct sbk_image_record_info {
	uint32_t pos;
	size_t size;
};

static int sbk_image_get_record_info(const struct sbk_slot *slot, uint16_t tag,
				     struct sbk_image_record_info *info)
{
	struct sbk_image_rec_hdr rhdr;

	while (true) {
		info->pos += info->size;
		if (sbk_slot_read(slot, info->pos, &rhdr, sizeof(rhdr)) != 0) {
			break;
		}

		if (rhdr.len < sizeof(rhdr)) { /* stop at invalid entries */
			break;
		}

		info->size = rhdr.len;
		if (rhdr.tag == tag) {
			break;
		}
	}

	return (rhdr.tag == tag) ? 0 : -SBK_EC_ENOENT;
}

static int sbk_image_get_record_pos(const struct sbk_slot *slot, uint16_t tag,
				    uint32_t *pos)
{
	struct sbk_image_record_info info = {
		.pos = 0U,
		.size = 0U,
	};
	int rc;

	rc = sbk_image_get_record_info(slot, tag, &info);
	if (rc != 0) {
		goto end;
	}

	*pos = info.pos;
end:
	return rc;
}

static int sbk_image_get_tagdata(const struct sbk_slot *slot, uint16_t tag,
				 void *data, size_t size)
{
	struct sbk_image_record_info info = {
		.pos = 0U,
		.size = 0U,
	};
	size_t rdsize;
	int rc;

	rc = sbk_image_get_record_info(slot, tag, &info);
	if (rc != 0) {
		goto end;
	}

	rdsize = SBK_MIN(size, info.size);
	rc = sbk_slot_read(slot, info.pos, data, rdsize);
end:
	return rc;
}

static int sbk_crypto_mem_read(const void *ctx, uint32_t off, void *data,
			       size_t len)
{
	const uint8_t *src = (const uint8_t *)ctx;

	memcpy(src, data, len);
	return 0;
}

static bool sbk_image_product_dependency_ok(const struct sbk_slot *slot,
					    const struct sbk_image_info *info)
{
	const struct sbk_product *product = sbk_get_product();
	uint16_t tag = info->product_dep_tag;
	uint32_t dcnt = 0U, mcnt = 0U;
	bool rv = false;

	if (product == NULL) {
		rv = true;
		goto end;
	}

	struct sbk_product_dep_info pdi;
	const struct sbk_crypto_read_ctx read_ctx = {
		.read = sbk_crypto_mem_read,
		.ctx = (void *)&product->name[0],
	};
	const struct sbk_crypto_hash_ctx hash_ctx = {
		.hash = (void *)&pdi.phash[0],
		.hash_size = SBK_IMAGE_HASH_SIZE,
	};
	const size_t pnsize = product->name_size;

	while (true) {
		uint32_t product_hash;

		if (sbk_image_get_tagdata(slot, tag, &pdi, sizeof(pdi)) != 0) {
			break;
		}

		dcnt++;
		tag = pdi.next_tag;

		if (sbk_crypto_hash_vrfy(&hash_ctx, &read_ctx, pnsize) != 0) {
			continue;

			struct sbk_version_range range = pdi.vrange;
			if (!sbk_product_version_in_range(&range)) {
				continue;
			}

			mcnt++;
		}

		if ((mcnt == 0U) && (dcnt > 0)) {
			goto end;
		}
	}

	rv = true;

end:
	return rv;
}

static bool slot_dep_ok(const struct sbk_slot *slot, uint32_t di_address,
			struct sbk_version_range *range)
{
	const uint16_t tag = SBK_IMAGE_INFO_TAG;
	struct sbk_image_info info;
	uint32_t address;
	bool rv = false;

	if (sbk_image_get_tagdata(slot, tag, &info, sizeof(info)) != 0) {
		goto end;
	}

	if (!sbk_version_in_range(&info.image_version, range)) {
		goto end;
	}

	address = info.image_offset;
	if (sbk_slot_address(slot, &address) != 0) {
		goto end;
	}

	if (di_address != address) {
		goto end;
	}

	rv = true;
end:
	return rv;
}

static bool sbk_image_image_dependency_ok(const struct sbk_slot *slot,
					  const struct sbk_image_info *info)
{
	uint16_t tag = info->image_dep_tag;
	uint32_t dcnt = 0U, mcnt = 0U;
	bool rv = false;

	while (true) {
		struct sbk_image_dep_info idi;

		if (sbk_image_get_tagdata(slot, tag, &idi, sizeof(idi)) != 0) {
			break;
		}

		dcnt++;
		tag = idi.next_tag;

		uint32_t dep_addr = idi.image_start_address;
		struct sbk_slot dslot;
		uint8_t dslot_no = 0U;

		while (true) {
			if (sbk_open_destination_slot(&dslot, dslot_no) != 0) {
				break;
			}

			if (slot_dep_ok(&dslot, dep_addr, &idi.vrange)) {
				mcnt++;
			}

			dslot_no++;
			(void)sbk_slot_close(&dslot);
		}
	}

	if (mcnt == dcnt) {
		rv = true;
	}

	return rv;
}

static bool sbk_image_info_found(const struct sbk_slot *slot,
				 struct sbk_image_info *info)
{
	const uint16_t tag = SBK_IMAGE_INFO_TAG;
	const size_t isz = sizeof(struct sbk_image_info);

	return sbk_image_get_tagdata(slot, tag, info, sizeof(info)) == 0;
}

static bool sbk_image_local_confirmed(const struct sbk_slot *slot)
{
	size_t slen;
	uint8_t buf[sizeof(SBK_IMAGE_STATE_SCONF_MAGIC) - 1];
	size_t blen = sizeof(buf);
	bool rv = false;

	if (sbk_slot_size(slot, &slen) != 0) {
		goto end;
	}

	if (sbk_slot_read(slot, slen - blen, &buf, blen) != 0) {
		goto end;
	}

	if (memcmp(buf, SBK_IMAGE_STATE_SCONF_MAGIC, blen) == 0) {
		rv = true;
	}

end:
	return rv;
}

static bool sbk_image_in_exe_slot(const struct sbk_slot *slot,
				  const struct sbk_image_info *info)
{
	uint32_t addr = info->image_offset;
	bool rv = false;

	if ((sbk_slot_address(slot, &addr) == 0) &&
	    (addr == info->image_start_address)) {
		rv = true;
	}

	return rv;
}

void sbk_image_init_state(const struct sbk_slot *slot,
			  struct sbk_image_state *st)
{
	struct sbk_image_info *info = &st->info;

	SBK_IMAGE_STATE_CLR(st->state, SBK_IMAGE_STATE_FULL);
	if (sbk_image_info_found(slot, info)) {
		SBK_IMAGE_STATE_SET(st->state, SBK_IMAGE_STATE_IINF);
	} else {
		return;
	}

	if (sbk_image_product_dependency_ok(slot, info)) {
		SBK_IMAGE_STATE_SET(st->state, SBK_IMAGE_STATE_PDEP);
	}

	if (sbk_image_image_dependency_ok(slot, info)) {
		SBK_IMAGE_STATE_SET(st->state, SBK_IMAGE_STATE_IDEP);
	}

	if (SBK_IMAGE_FLAG_ISSET(info->image_flags, SBK_IMAGE_FLAG_CONF)) {
		SBK_IMAGE_STATE_SET(st->state, SBK_IMAGE_FLAG_CONF);
	}

	if (sbk_image_local_confirmed(slot)) {
		SBK_IMAGE_STATE_SET(st->state, SBK_IMAGE_FLAG_CONF);
	}

	if (sbk_image_in_exe_slot(slot, info)) {
		SBK_IMAGE_STATE_SET(st->state, SBK_IMAGE_STATE_INRS);
	}
}

static void sbk_image_get_hmac_key(const uint8_t *salt, size_t salt_size,
				   uint8_t *otk, size_t otk_size)
{
	const uint8_t context[] = SBK_IMAGE_HMAC_CONTEXT;
	const struct sbk_key *privkey = sbk_get_private_key();

	if (privkey == NULL) {
		return;
	}

	const struct sbk_crypto_kxch_ctx kxch_ctx = {
		.pkey = privkey->key,
		.pkey_size = privkey->key_size,
		.salt = salt,
		.salt_size = salt_size,
		.context = context,
		.context_size = sizeof(context) - 1,
	};

	sbk_crypto_kxch(&kxch_ctx, otk, otk_size);
	sbk_crypto_cwipe(context, sizeof(context));
}

static void sbk_image_get_ciph_key(const uint8_t *salt, size_t salt_size,
				   uint8_t *otk, size_t otk_size)
{
	const uint8_t context[] = SBK_IMAGE_CIPH_CONTEXT;
	const struct sbk_key *privkey = sbk_get_private_key();

	if (privkey == NULL) {
		return;
	}

	const struct sbk_crypto_kxch_ctx kxch_ctx = {
		.pkey = privkey->key,
		.pkey_size = privkey->key_size,
		.salt = salt,
		.salt_size = salt_size,
		.context = context,
		.context_size = sizeof(context) - 1,
	};

	sbk_crypto_kxch(&kxch_ctx, otk, otk_size);
	sbk_crypto_cwipe(context, sizeof(context));
}

struct sbk_crypto_pslot_ctx {
	struct sbk_slot *slot;
	uint32_t soff;
};

static int sbk_crypto_pslot_read(const void *ctx, uint32_t off, void *data,
				 size_t len)
{
	const struct sbk_crypto_pslot_ctx *pctx =
		(const struct sbk_crypto_pslot_ctx *)ctx;

	return sbk_slot_read(pctx->slot, pctx->soff + off, data, len);
}

static bool sbk_image_sldr_hmac_ok(const struct sbk_slot *slot,
				   const struct sbk_image_sldr_auth *auth,
				   uint8_t *otk, size_t otk_size)
{
	const uint16_t tag = SBK_IMAGE_SLDR_TAG;
	const struct sbk_crypto_hmac_ctx hmac_ctx = {
		.key = (void *)otk,
		.key_size = otk_size,
		.hmac = (void *)&auth->hmac[0],
		.hmac_size = SBK_IMAGE_HMAC_SIZE,
	};
	const struct sbk_crypto_pslot_ctx pslot_ctx = {
		.slot = slot,
		.soff = 0U,
	};
	const struct sbk_crypto_read_ctx read_ctx = {
		.read = sbk_crypto_pslot_read,
		.ctx = (void *)&pslot_ctx,
	};
	uint32_t len;
	bool rv = false;

	if (sbk_image_get_record_pos(slot, tag, &len) != 0) {
		goto end;
	}

	if (sbk_crypto_hmac_vrfy(&hmac_ctx, &read_ctx, len) == 0) {
		rv = true;
	}

end:
	return rv;
}

bool sbk_image_sldr_auth_ok(const struct sbk_slot *slot)
{
	const uint16_t tag = SBK_IMAGE_SLDR_TAG;
	struct sbk_image_sldr_auth auth;
	uint8_t otk[SBK_IMAGE_HMAC_KEY_SIZE];
	bool rv = false;

	if (sbk_image_get_tagdata(slot, tag, &auth, sizeof(auth)) != 0) {
		goto end;
	}

	sbk_image_get_hmac_key(&auth.salt[0], SBK_IMAGE_SALT_SIZE, otk,
			       sizeof(otk));

	rv = sbk_image_sldr_hmac_ok(slot, &auth, otk, sizeof(otk));
	sbk_crypto_cwipe(otk, sizeof(otk));
end:
	return rv;
}

static bool sbk_image_sfsl_sign_ok(const struct sbk_slot *slot,
				   const struct sbk_image_sfsl_auth *auth,
				   uint8_t *pubkey, size_t pubkey_size)
{
	const uint16_t tag = SBK_IMAGE_SFSL_TAG;
	const struct sbk_crypto_sigp256_ctx p256_ctx = {
		.pubkey = (void *)pubkey,
		.pubkey_size = pubkey_size,
		.signature = (void *)&auth->sign[0],
		.signature_size = SBK_IMAGE_SIGN_SIZE,
	};
	const struct sbk_crypto_pslot_ctx pslot_ctx = {
		.slot = slot,
		.soff = 0U,
	};
	const struct sbk_crypto_read_ctx read_ctx = {
		.read = sbk_crypto_pslot_read,
		.ctx = (void *)&pslot_ctx,
	};
	uint32_t len;
	bool rv = false;

	if (sbk_image_get_record_pos(slot, tag, &len) != 0) {
		goto end;
	}

	if (sbk_crypto_sigp256_vrfy(&p256_ctx, &read_ctx, len) == 0) {
		rv = true;
	}

end:
	return rv;
}

static bool sbk_image_sfsl_pubkey_ok(const struct sbk_image_sfsl_auth *auth,
				     const uint8_t *pubkey, size_t pksize)
{
	const struct sbk_crypto_read_ctx read_ctx = {
		.read = sbk_crypto_mem_read,
		.ctx = (void *)pubkey,
	};
	const struct sbk_crypto_hash_ctx hash_ctx = {
		.hash = (void *)auth->pk_hash[0],
		.hash_size = SBK_IMAGE_HASH_SIZE,
	};
	bool rv = false;

	if (sbk_crypto_hash_vrfy(&hash_ctx, &read_ctx, pksize) == 0) {
		rv = true;
	}

	return rv;
}

bool sbk_image_sfsl_auth_ok(const struct sbk_slot *slot)
{
	const struct sbk_key *pubkey = sbk_get_public_key();
	const uint16_t tag = SBK_IMAGE_SFSL_TAG;
	const size_t pksz = SBK_IMAGE_PUBK_SIZE;
	struct sbk_image_sfsl_auth auth;
	size_t idx = 0U;
	bool rv = false;

	if (sbk_image_get_tagdata(slot, tag, &auth, sizeof(auth)) != 0) {
		goto end;
	}

	if (pubkey == NULL) {
		goto end;
	}

	while ((!sbk_image_sfsl_pubkey_ok(&auth, pubkey->key + idx, pksz)) &&
	       (idx < pubkey->key_size)) {
		idx += pksz;
	}

	if (idx == pubkey->key_size) {
		goto end;
	}

	rv = sbk_image_sfsl_sign_ok(slot, &auth, pubkey->key + idx, pksz);
end:
	return rv;
}

bool sbk_image_hash_ok(const struct sbk_slot *slot,
		       const struct sbk_image_info *info)
{
	const struct sbk_crypto_pslot_ctx pslot_ctx = {
		.slot = slot,
		.soff = info->image_offset,
	};
	const struct sbk_crypto_read_ctx read_ctx = {
		.read = sbk_crypto_pslot_read,
		.ctx = (void *)&pslot_ctx,
	};
	const struct sbk_crypto_hash_ctx hash_ctx = {
		.hash = (void *)info->image_hash[0],
		.hash_size = SBK_IMAGE_HASH_SIZE,
	};
	bool rv = false;

	if (sbk_crypto_hash_vrfy(&hash_ctx, &read_ctx, info->image_size) == 0) {
		rv = true;
	}

	return rv;
}

bool sbk_image_sfsl_state(const struct sbk_slot *slot,
			  struct sbk_image_state *st)
{
	if (sbk_image_sfsl_auth_ok(slot)) {
		SBK_IMAGE_STATE_SET(st->state, SBK_IMAGE_STATE_BAUT);
	}

	if (sbk_image_hash_ok(slot, &st->info)) {
		SBK_IMAGE_STATE_SET(st->state, SBK_IMAGE_STATE_BHSH);
	}
}

static bool sbk_image_is_valid(const struct sbk_slot *slot,
			       struct sbk_image_state *st)
{
	bool rv = false;

	if (sbk_image_get_state(slot, st) != 0) {
		goto end;
	}

	struct sbk_image_auth ia;
	size_t iasz = sizeof(struct sbk_image_auth);

	if (sbk_image_get_tagdata(slot, SBK_IMAGE_AUTH_TAG, &ia, iasz) != 0) {
		goto end;
	};

	if (sbk_image_hmac_ok(slot, &ia, &st->im)) {
		rv = true;
	}

end:
	return rv;
}

static bool sbk_image_is_valid_header(const struct sbk_slot *slot,
				      struct sbk_image_state *st)
{
	bool rv = false;

	if (sbk_image_get_state(slot, st) != 0) {
		goto end;
	}

	struct sbk_image_auth ia;
	size_t iasz = sizeof(struct sbk_image_auth);

	if (sbk_image_get_tagdata(slot, SBK_IMAGE_AUTH_TAG, &ia, iasz) != 0) {
		goto end;
	};

	memcpy(&ia.fhmac, &ia.hhmac, SBK_IMAGE_HMAC_SIZE);

	struct sbk_image_meta im = st->im;

	im.image_size = im.image_offset;

	if (sbk_image_hmac_ok(slot, &ia, &im)) {
		rv = true;
	}

end:
	return rv;
}

struct sbk_boot_slot_ctx {
	const struct sbk_slot *slt;
	uint32_t split_pos;
	uint32_t split_jmp;
};

int boot_slot_read(const void *ctx, uint32_t off, void *data, size_t len)
{
	struct sbk_boot_slot_ctx *bsctx = (struct sbk_boot_slot_ctx *)ctx;
	uint8_t *data8 = (uint8_t *)data;
	int rc;

	if (bsctx->split_pos == 0U) {
		/* setup the split slot (authentication data is after
		 * image) */
		const size_t meta_sz = sizeof(struct sbk_image_meta);
		struct sbk_image_record_info info = {.pos = 0U, .size = 0U};
		struct sbk_image_meta meta;

		rc = sbk_image_get_record_info(bsctx->slt, SBK_IMAGE_AUTH_TAG,
					       &info);
		if (rc != 0) {
			goto end;
		}

		rc = sbk_image_get_tagdata(bsctx->slt, SBK_IMAGE_META_TAG, &meta,
					   meta_sz);
		if (rc != 0) {
			goto end;
		}

		bsctx->split_pos = info.pos + info.size;
		bsctx->split_jmp = meta.image_offset + meta.image_size;
	}

	if (off < bsctx->split_pos) {
		size_t rdlen = SBK_MIN(len, bsctx->split_pos - off);

		rc = sbk_slot_read(bsctx->slt, off + bsctx->split_jmp, data8,
				   rdlen);

		if (rc != 0) {
			goto end;
		}

		data8 += rdlen;
		off += rdlen;
		len -= rdlen;
	}

	if (len != 0U) {
		rc = sbk_slot_read(bsctx->slt, off, data8, len);
	}

end:
	return rc;
}

int boot_slot_size(const void *ctx, size_t *size)
{
	struct sbk_boot_slot_ctx *bsctx = (struct sbk_boot_slot_ctx *)ctx;

	return sbk_slot_size(bsctx->slt, size);
}

int boot_slot_address(const void *ctx, uint32_t *addr)
{
	struct sbk_boot_slot_ctx *bsctx = (struct sbk_boot_slot_ctx *)ctx;

	return sbk_slot_address(bsctx->slt, addr);
}

bool sbk_image_can_run(const struct sbk_slot *slt, struct sbk_image_state *st)
{
	struct sbk_boot_slot_ctx bsctx = {
		.slt = slt, .split_pos = 0U, .split_jmp = 0U};
	struct sbk_slot bslt = {
		.ctx = (void *)&bsctx,
		.read = boot_slot_read,
		.size = boot_slot_size,
		.address = boot_slot_address,
	};
	bool rv = false;

	SBK_IMAGE_STATE_CLR_FLAGS(st->state_flags);
	if (!sbk_image_is_valid(&bslt, st)) {
		goto end;
	}

	if (!SBK_IMAGE_STATE_IS_RUNNABLE(st->state_flags)) {
		goto end;
	}

	rv = true;
end:
	return rv;
}

#if CONFIG_SBK_IMAGE_AUTHENTICATE == 0
bool sbk_image_is_authentic(const struct sbk_slot *slt)
{
	return true;
}
#else  /* todo add signature check */
bool sbk_image_is_authentic(const struct sbk_slot *slt)
{
	return true;
}
#endif /* CONFIG_SBK_IMAGE_AUTHENTICATE */

static bool sbk_image_can_upgrade(const struct sbk_slot *dst,
				  const struct sbk_slot *src)
{
	struct sbk_image_state dst_st, src_st;
	bool rv = false;

	SBK_IMAGE_STATE_CLR_FLAGS(dst_st.state_flags);
	SBK_IMAGE_STATE_CLR_FLAGS(src_st.state_flags);
	(void)sbk_image_get_state(dst, &dst_st);

	if (!sbk_image_is_authentic(src)) {
		goto end;
	}

	if (!sbk_image_is_valid_header(src, &src_st)) {
		goto end;
	}

	if (src_st.im.image_sequence_number >= dst_st.im.image_sequence_number) {
		rv = true;
	}

	if ((!rv) && (!SBK_IMAGE_STATE_ICONF_IS_SET(dst_st.state_flags))) {
		rv = true;
	}

	if ((!rv) && (!SBK_IMAGE_STATE_SCONF_IS_SET(dst_st.state_flags))) {
		rv = true;
	}

end:
	return rv;
}

static int sbk_image_cipher(const struct sbk_image_meta *meta, uint32_t offset,
			    void *data, size_t len)
{
	const size_t cbsize = sbk_crypto_cipher_block_size();
	const size_t cssize = sbk_crypto_cipher_state_size();
	const size_t cksize = sbk_crypto_kxch_km_size();
	uint8_t dbuf[cbsize], cbuf[cbsize], est[cssize], otk[cksize];
	uint8_t *data8 = (uint8_t *)data;
	int rc;

	if (offset < meta->image_offset) {
		return -SBK_EC_EINVAL;
	}

	sbk_image_get_ciph_key(meta, otk);

	while (len != 0U) {
		uint32_t bcnt = (offset - meta->image_offset) / cbsize;
		uint32_t boff = bcnt * cbsize + meta->image_offset;

		memset(dbuf, 0, cbsize);
		memcpy(dbuf + (offset - boff), data8, cbsize - (offset - boff));
		sbk_crypto_cipher_init(est, otk, sizeof(otk), bcnt);
		sbk_crypto_cipher(cbuf, dbuf, cbsize, est);
		while ((len != 0U) && ((offset - boff) < cbsize)) {
			(*data8) = cbuf[offset - boff];
			data8++;
			offset++;
			len--;
		}
	}

	sbk_crypto_cwipe(dbuf, sizeof(dbuf));
	sbk_crypto_cwipe(cbuf, sizeof(cbuf));
	sbk_crypto_cwipe(est, sizeof(est));
	sbk_crypto_cwipe(otk, sizeof(otk));
	return rc;
}

int sbk_image_read(const struct sbk_slot *slot, uint32_t off, void *data,
		   size_t len)
{
	uint8_t *data8 = (uint8_t *)data;
	struct sbk_image_meta im;
	int rc;

	rc = sbk_image_get_tagdata(slot, SBK_IMAGE_META_TAG, &im, sizeof(im));
	if (rc != 0) {
		goto end;
	}

	if (off < im.image_offset) {
		size_t rdlen = SBK_MIN(len, im.image_offset - off);
		rc = sbk_slot_read(slot, off, data8, rdlen);
		if ((rc != 0) || (rdlen == len)) {
			goto end;
		}

		off += rdlen;
		len -= rdlen;
		data8 += rdlen;
	}

	/* Limit read to image data */
	if ((off + len) > (im.image_offset + im.image_size)) {
		len = (im.image_offset + im.image_size - off);
	}

	uint32_t saddr = im.image_offset;
	if ((!SBK_IMAGE_ENCRYPTED(im.image_flags)) ||
	    (sbk_slot_address(slot, &saddr) != 0) ||
	    (saddr != im.image_start_address)) {
		rc = sbk_slot_read(slot, off, data8, len);
	} else {
		rc = sbk_image_cipher(&im, off, data8, len);
	}

end:
	return rc;
}

static int stream_read(const void *ctx, uint32_t off, void *data, size_t len)
{
	const struct sbk_stream_image_ctx *si_ctx =
		(const struct sbk_stream_image_ctx *)ctx;
	uint8_t *data8 = (uint8_t *)data;
	int rc = 0;

	while ((off < si_ctx->soff) && (len != 0U)) {
		size_t rdlen = SBK_MIN(si_ctx->soff - off, len);
		rc = sbk_slot_read(si_ctx->slt, off, data8, rdlen);
		if (rc != 0) {
			goto end;
		}

		len -= rdlen;
		off += rdlen;
		data8 += rdlen;
	}

	if (len != 0U) {
		memcpy(data8, si_ctx->sdata, len);
	}

end:
	return rc;
}

int stream_address(const void *ctx, uint32_t *address)
{
	const struct sbk_stream_image_ctx *si_ctx =
		(const struct sbk_stream_image_ctx *)ctx;

	return sbk_slot_address(si_ctx->slt, address);
}

int sbk_stream_image_flush(struct sbk_stream_image_ctx *ctx, size_t len)
{
	uint8_t buf[SBK_IMAGE_WBS];
	struct sbk_slot stream_slot = {
		.ctx = (void *)ctx,
		.read = stream_read,
		.address = stream_address,
	};
	int rc;

	if ((ctx->soff == 0U) && (ctx->validate) &&
	    (!sbk_image_can_upgrade(ctx->slt, &stream_slot))) {
		return -SBK_EC_EFAULT;
	}

	while (len != 0) {
		size_t rdlen = SBK_MIN(len, sizeof(buf));

		rc = sbk_image_read(&stream_slot, ctx->soff, buf, rdlen);
		if (rc != 0) {
			goto end;
		}

		rc = sbk_slot_prog(ctx->slt, ctx->soff, buf, rdlen);
		if (rc != 0) {
			goto end;
		}

		ctx->soff += rdlen;
		len -= rdlen;
	}

end:
	return rc;
}

/**
 * The validation read method can be used to validate a image that is
 * spread over both a decrypted slot and an encrypted slot. The method
 * relies on the use of symmetrical encryption and that sbk_image_read()
 * encrypts the data when the image is located in a slot where the run
 * address equals to the image offset). Two types of spread images are
 * supported:
 * 1. Where the image starts in the decrypted slot:
 *    The data in the decrypted slot can be read using sbk_slot_read(),
 *    The data in the encrypted slot is decrypted by using
 * sbk_image_read().
 * 2. Where the image starts in the encrypted slot:
 *    The data in the encrypted slot is decrypted by using
 * sbk_image_read(), The image in the decrypted slot can be read using
 * sbk_slot_read().
 */
// struct sbk_validation_ctx {
// 	struct sbk_slot *dslt; /* decr. slot */
// 	struct sbk_slot *eslt; /* encr. slot */
// 	uint32_t off; /* switch over from encr. to decr. or vice versa */
// 	bool start_in_dslt;
// };

// int sbk_validation_read(const void *ctx, uint32_t off, void *data,
// size_t len)
// {
// 	const struct sbk_validation_ctx *vctx =
// 		(const struct sbk_validation_ctx *)ctx;
// 	uint8_t *data8 = (uint8_t *)data;
// 	int rc;

// 	while ((off < vctx->off) && (len != 0U)) {
// 		size_t rdlen = SBK_MIN(vctx->off - off, len);
// 		if (vctx->start_in_dslt) {
// 			rc = sbk_slot_read(vctx->dslt, off, data8,
// rdlen); 		} else { 			rc =
// sbk_image_read(vctx->eslt, off, data8, len);
// 		}

// 		if (rc != 0) {
// 			goto end;
// 		}

// 		len -= rdlen;
// 		off += rdlen;
// 		data8 += rdlen;
// 	}

// 	if (len != 0U) {
// 		if (vctx->start_in_dslt) {
// 			rc = sbk_image_read(vctx->eslt, off, data8, len);
// 		} else {
// 			rc = sbk_slot_read(vctx->dslt, off, data8, len);
// 		}
// 	}

// end:
// 	return rc;
// }

// int sbk_validation_address(const void *ctx, uint32_t *address)
// {
// 	const struct sbk_validation_ctx *vctx =
// 		(const struct sbk_validation_ctx *)ctx;

// 	return sbk_slot_address(vctx->dslt, address);
// }
