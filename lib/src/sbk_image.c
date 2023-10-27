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
#include "private_key.h"

#define SBK_IMAGE_CONFIRMED(flags)						\
	((flags & SBK_IMAGE_FLAG_CONFIRMED) == SBK_IMAGE_FLAG_CONFIRMED)
#define SBK_IMAGE_ENCRYPTED(flags)                                              \
	((flags & SBK_IMAGE_FLAG_ENCRYPTED) == SBK_IMAGE_FLAG_ENCRYPTED)
#define SBK_IMAGE_ZLIB(flags)                                                   \
	((flags & SBK_IMAGE_FLAG_ZLIB) == SBK_IMAGE_FLAG_ZLIB)
#define SBK_IMAGE_VCDIFF(flags)                                                 \
	((flags & SBK_IMAGE_FLAG_VCDIFF) == SBK_IMAGE_FLAG_VCDIFF)
#define SBK_IMAGE_ALIGNMENT(flags)						\
	(1 << ((flags & SBK_IMAGE_FLAG_AL_MASK) >> SBK_IMAGE_FLAG_AL_SHIFT))

static bool sbk_image_tag_is_odd_parity(uint16_t data)
{
	data ^= data >> 8;
	data ^= data >> 4;
	data &= 0xf;
	return ((0x6996 >> data) & 1U) == 1U;
}

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

		if (!sbk_image_tag_is_odd_parity(rhdr.tag)) {
			break;
		}

		info->size = rhdr.len;
		if (rhdr.tag == tag) {
			break;
		}

	}

	return (rhdr.tag == tag) ? -SBK_EC_ENOENT : 0;
}

static int sbk_image_get_tagdata(const struct sbk_slot *slot, uint16_t tag,
				 void *data, size_t size)
{
	struct sbk_image_record_info info = { .pos = 0U, .size = 0U, };
	size_t rdsize;
	int rc;

	rc = sbk_image_get_record_info(slot, tag, &info);
	if (rc != 0) {
		goto end;
	}

	rdsize = SBK_MIN(size, info.size);
	return sbk_image_read_tag_data(slot, info.pos, data, rdsize);
end:
	return rc;
}

static unsigned char sbk_image_kslot_idx = SBK_IMAGE_DEFAULT_KSLOTIDX;

void sbk_image_set_kslot(unsigned char kidx)
{
	sbk_image_kslot_idx = kidx;
}

void sbk_image_reset_kslot(unsigned char kidx)
{
	sbk_image_kslot_idx = SBK_IMAGE_DEFAULT_KSLOTIDX;
}

static void sbk_image_get_ltkey(void *ltkey, size_t klen)
{
	struct sbk_slot key_slot;

	if ((sbk_open_key_slot(&key_slot, sbk_image_kslot_idx) != 0) ||
	    (sbk_slot_read(&key_slot, 0U, ltkey, klen) != 0)) {
		memset(ltkey, 0U, klen);
	}

}

static void sbk_image_get_hmac_key(const struct sbk_image_meta *meta,
				   uint8_t *otk)
{
	uint8_t prk[sbk_crypto_kxch_prk_size()];
	uint8_t ltkey[SBK_IMAGE_LTKEY_SIZE];
	const size_t salt_sz = SBK_IMAGE_SALT_SIZE;

	sbk_image_get_ltkey(ltkey, sizeof(ltkey));
	sbk_crypto_kxch_init(prk, meta->salt, salt_sz, ltkey, sizeof(ltkey));
	sbk_crypto_kxch_final(otk, prk, SBK_IMAGE_HMAC_CONTEXT,
			      sizeof(SBK_IMAGE_HMAC_CONTEXT) - 1);
}

static void sbk_image_get_ciph_key(const struct sbk_image_meta *meta,
				   uint8_t *otk)
{
	uint8_t prk[sbk_crypto_kxch_prk_size()];
	uint8_t ltkey[SBK_IMAGE_LTKEY_SIZE];
	const size_t salt_sz = SBK_IMAGE_SALT_SIZE;

	sbk_image_get_pkey(ltkey, sizeof(ltkey));
	sbk_crypto_kxch_init(prk, meta->salt, salt_sz, ltkey, sizeof(ltkey));
	sbk_crypto_kxch_final(otk, prk, SBK_IMAGE_CIPH_CONTEXT,
			      sizeof(SBK_IMAGE_CIPH_CONTEXT) - 1);
}

bool sbk_image_hmac_ok(const struct sbk_slot *slot,
		       const struct sbk_image_auth *auth,
		       const struct sbk_image_meta *meta)
{
	struct sbk_image_record_info info = { .pos = 0U, .size = 0U,};
	uint32_t pos, len;
	uint8_t otk[sbk_crypto_kxch_km_size()];
	uint8_t sbuf[sbk_crypto_auth_state_size()];
	uint8_t ctag[SBK_IMAGE_HMAC_SIZE];
	bool rv = false;

	if (sbk_image_get_record_info(slot, SBK_IMAGE_AUTH_TAG, &info) != 0) {
		goto end;
	}

	pos = info.pos + info.size;
	len = meta->image_offset + meta->image_size - pos;
	sbk_image_get_auth_key(meta, otk);
	sbk_crypto_auth_init(sbuf, otk, sizeof(otk));
	sbk_crypto_cwipe(otk, sizeof(otk));

	while (len != 0) {
		uint8_t buf[64];
		uint32_t rdlen = MIN(len, sizeof(buf));

		if (sbk_slot_read(slot, pos, buf, rdlen) != 0) {
			goto end;
		}

		sbk_crypto_auth_update(sbuf, buf, rdlen);
		len -= rdlen;
		pos += rdlen;
	}

	sbk_crypto_auth_final(ctag, sbuf);
	if (sbk_crypto_compare(ctag, auth->fhmac, sizeof(ctag)) == 0) {
		rv = true;
	}

end:
	sbk_crypto_cwipe(sbuf, sizeof(sbuf));

	return rv;
}

static bool sbk_image_product_dependency_ok(const struct sbk_slot *slot,
					    const struct sbk_image_meta *meta)
{
	uint16_t tag = meta->product_dep_tag;
	uint32_t dcnt = 0U, mcnt = 0U;
	bool rv = false;

	while (true) {
		struct sbk_product_dep_info pdi;
		uint32_t product_hash;

		if (sbk_image_get_tagdata(slot, tag, &pdi, sizeof(pdi)) != 0) {
			break;
		}

		dcnt++;
		tag = pdi.next_tag;
		product_hash = pdi.product_hash;

		if (!sbk_product_hash_match(&product_hash)) {
			continue;
		}

		struct sbk_version_range range = pdi.vrange;
		if (!sbk_product_version_in_range(&range)) {
			continue;
		}

		mcnt++;
	}

	if ((mcnt == 0U) && (dcnt > 0)) {
		goto end;
	}

	rv = true;

end:
	return rv;
}

static bool slot_dep_ok(const struct sbk_slot *slot, uint32_t di_address,
			struct sbk_version_range *range)
{
	struct sbk_image_meta meta;
	uint32_t address;
	bool rv = false;

	if (sbk_image_get_tagdata(slot, SBK_IMAGE_META_TAG, (void *)&meta,
				  sizeof(meta)) != 0) {
		goto end;
	}

	if (!sbk_version_in_range(&meta.image_version, range)) {
		goto end;
	}

	address = meta.image_offset;
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
					  const struct sbk_image_meta *meta)
{
	uint16_t tag = meta->image_dep_tag;
	;
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

int sbk_image_get_version(const struct sbk_slot *slot,
			  struct sbk_version *version)
{
	struct sbk_image_meta im;
	int rc;

	rc = sbk_image_get_tagdata(slot, SBK_IMAGE_META_TAG, &im, sizeof(im));
	if (rc != 0) {
		goto end;
	}

	memcpy(version, &im.image_version, sizeof(struct sbk_version));
end:
	return rc;
}

int sbk_image_get_length(const struct sbk_slot *slot, size_t *length)
{
	struct sbk_image_meta im;
	int rc;

	*length = 0U;
	rc = sbk_image_get_tagdata(slot, SBK_IMAGE_META_TAG, &im, sizeof(im));
	if (rc != 0) {
		goto end;
	}

	*length = im.image_offset + im.image_size;
end:
	return rc;
}

int sbk_image_get_state(const struct sbk_slot *slot, struct sbk_image_state *st)
{
	struct sbk_image_meta im;
	int rc;

	rc = sbk_image_get_tagdata(slot, SBK_IMAGE_META_TAG, &im, sizeof(im));
	if (rc != 0) {
		goto end;
	}

	st->im = im;

	while (!SBK_IMAGE_STATE_PDEP_IS_SET(st->state_flags)) {
		if (!sbk_image_product_dependency_ok(slot, &im)) {
			break;
		}

		SBK_IMAGE_STATE_PDEP_SET(st->state_flags);
	}

	while (!SBK_IMAGE_STATE_IDEP_IS_SET(st->state_flags)) {
		if (!sbk_image_image_dependency_ok(slot, &im)) {
			break;
		}

		SBK_IMAGE_STATE_IDEP_SET(st->state_flags);
	}

	while (!SBK_IMAGE_STATE_ICONF_IS_SET(st->state_flags)) {
		if (!SBK_IMAGE_CONFIRMED(im.image_flags)) {
			break;
		}

		SBK_IMAGE_STATE_ICONF_SET(st->state_flags);
	}

	while (!SBK_IMAGE_STATE_SCONF_IS_SET(st->state_flags)) {
		size_t slen;

		if (sbk_slot_size(slot, &slen) != 0) {
			break;
		}

		uint8_t buf[sizeof(SBK_IMAGE_STATE_SCONF_MAGIC) - 1];
		size_t blen = sizeof(buf);

		if (sbk_slot_read(slot, slen - blen, &buf, blen) != 0) {
			break;
		}

		if (memcmp(buf, SBK_IMAGE_STATE_SCONF_MAGIC, blen) != 0) {
			break;
		}

		SBK_IMAGE_STATE_SCONF_SET(st->state_flags);
	}

	while (!SBK_IMAGE_STATE_INRS_IS_SET(st->state_flags)) {
		uint32_t addr = im.image_offset;

		if ((sbk_slot_address(slot, &addr) != 0) ||
		    (addr != im.image_start_address)) {
			break;
		}

		SBK_IMAGE_STATE_INRS_SET(st->state_flags);
	}

end:
	return rc;
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
	struct sbk_slot *slt;
	uint32_t split_pos;
	uint32_t split_jmp;
};

int boot_slot_read(const void *ctx, uint32_t off, void *data, size_t len)
{
	struct sbk_boot_slot_ctx *bsctx = (struct sbk_boot_slot_ctx *)ctx;
	uint8_t data8 = (uint8_t *)data;
	int rc;

	if (bsctx->split_pos == 0U) {
		/* setup the split slot (authentication data is after image) */
		const size_t meta_sz = sizeof(struct sbk_image_meta);
		struct sbk_image_record_info info = {.pos = 0U, .size = 0U};
		struct sbk_image_meta meta;

		rc = sbk_image_get_record_info(bsctx->slt, SBK_IMAGE_AUTH_TAG,
					       &info);
		if (rc != 0) {
			goto end;
		}

		rc = sbk_image_get_tagdata(bsctx->slt, SBK_IMAGE_META_TAG,
					   &meta, meta_sz);
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
		.slt = slt,
		.split_pos = 0U,
		.split_jmp = 0U};
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

#if CONFIG_SBK_IMAGE_AUTHENTICATE==0
bool sbk_image_is_authentic(const struct sbk_slot *slt)
{
	return true;
}
#else /* todo add signature check */
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

	if (src_st.im.image_sequence_number >=
	    dst_st.im.image_sequence_number) {
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
 * The validation read method can be used to validate a image that is spread
 * over both a decrypted slot and an encrypted slot. The method relies on the
 * use of symmetrical encryption and that sbk_image_read() encrypts the data
 * when the image is located in a slot where the run address equals to the
 * image offset).
 * Two types of spread images are supported:
 * 1. Where the image starts in the decrypted slot:
 *    The data in the decrypted slot can be read using sbk_slot_read(),
 *    The data in the encrypted slot is decrypted by using sbk_image_read().
 * 2. Where the image starts in the encrypted slot:
 *    The data in the encrypted slot is decrypted by using sbk_image_read(),
 *    The image in the decrypted slot can be read using sbk_slot_read().
 */
// struct sbk_validation_ctx {
// 	struct sbk_slot *dslt; /* decr. slot */
// 	struct sbk_slot *eslt; /* encr. slot */
// 	uint32_t off; /* switch over from encr. to decr. or vice versa */
// 	bool start_in_dslt;
// };

// int sbk_validation_read(const void *ctx, uint32_t off, void *data, size_t len)
// {
// 	const struct sbk_validation_ctx *vctx =
// 		(const struct sbk_validation_ctx *)ctx;
// 	uint8_t *data8 = (uint8_t *)data;
// 	int rc;

// 	while ((off < vctx->off) && (len != 0U)) {
// 		size_t rdlen = SBK_MIN(vctx->off - off, len);
// 		if (vctx->start_in_dslt) {
// 			rc = sbk_slot_read(vctx->dslt, off, data8, rdlen);
// 		} else {
// 			rc = sbk_image_read(vctx->eslt, off, data8, len);
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
