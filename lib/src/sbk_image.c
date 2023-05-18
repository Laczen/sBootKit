/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sbk/sbk_util.h"
#include "sbk/sbk_crypto.h"
#include "sbk/sbk_slot.h"
#include "sbk/sbk_image.h"
#include <string.h>

static bool sbk_image_is_confirmed(uint32_t flags)
{
	return ((flags & SBK_IMAGE_FLAG_CONFIRMED) == SBK_IMAGE_FLAG_CONFIRMED);
}

static bool sbk_image_is_encrypted(uint32_t flags)
{
	return ((flags & SBK_IMAGE_FLAG_ENCRYPTED) == SBK_IMAGE_FLAG_ENCRYPTED);
}

static bool sbk_image_tag_is_odd_parity(uint16_t data)
{
	data ^= data >> 8;
	data ^= data >> 4;
	data &= 0xf;
	return ((0x6996 >> data) & 1U) == 1U;
}

static int sbk_image_get_tag_pos(const struct sbk_slot *slot, uint32_t *pos,
				 uint16_t tag, uint16_t len)
{
	SBK_ASSERT(slot);

	struct sbk_image_rec_hdr rhdr;

	while (true) {
		if (sbk_slot_read(slot, *pos, &rhdr, sizeof(rhdr)) != 0) {
			goto end;
		}

		if (!sbk_image_tag_is_odd_parity(rhdr.tag)) {
			goto end;
		}

		if ((rhdr.tag == tag) && (rhdr.len == len)) {
			break;
		}

		*pos += rhdr.len;
	}

	return 0;
end:
	return -SBK_EC_ENOENT;
}

static int sbk_image_read_tag_data(const struct sbk_slot *slot, uint32_t pos,
				   void *data, size_t len)
{
	SBK_ASSERT(slot);

	return sbk_slot_read(slot, pos, data, len);
}

static int sbk_image_get_tagdata(const struct sbk_slot *slot, uint16_t tag,
				 void *data, size_t dlen)
{
	SBK_ASSERT(slot);

	int rc;
	uint32_t spos = 0U;

	rc = sbk_image_get_tag_pos(slot, &spos, tag, dlen);
	if (rc != 0) {
		goto end;
	}

	return sbk_image_read_tag_data(slot, spos, data, dlen);
end:
	return rc;
}

static void sbk_image_get_auth_key(const struct sbk_image_meta *meta, 
                                   uint8_t *otk)
{
        uint8_t prk[sbk_crypto_kxch_prk_size()];
        const size_t salt_sz = sizeof(((struct sbk_image_meta *)0)->salt);

        sbk_crypto_kxch_init(prk, meta->salt, salt_sz);
	sbk_crypto_kxch_final(otk, prk, SBK_IMAGE_AUTH_CONTEXT,
			      sizeof(SBK_IMAGE_AUTH_CONTEXT) - 1);
}

static void sbk_image_get_ciph_key(const struct sbk_image_meta *meta,
                                   uint8_t *otk)
{
        uint8_t prk[sbk_crypto_kxch_prk_size()];
        const size_t salt_sz = sizeof(((struct sbk_image_meta *)0)->salt);

        sbk_crypto_kxch_init(prk, meta->salt, salt_sz);
	sbk_crypto_kxch_final(otk, prk, SBK_IMAGE_ENCR_CONTEXT,
			      sizeof(SBK_IMAGE_ENCR_CONTEXT) - 1);
}

static int sbk_image_authentic(const struct sbk_slot *slot,
			       const uint8_t *tag, size_t tlen, bool full)
{
	SBK_ASSERT(slot);

	int rc;
	struct sbk_image_meta meta;
	uint32_t pos, len;
	uint8_t otk[sbk_crypto_kxch_km_size()];
	uint8_t sbuf[sbk_crypto_auth_state_size()];
	uint8_t buf[64];

        rc = sbk_image_get_tagdata(slot, SBK_IMAGE_META_TAG, (void *)&meta,
                                   sizeof(meta));
	if (rc != 0) {
		goto end;
	}
        
        pos = sizeof(struct sbk_image_auth);
	len = meta.image_offset - pos;

	if (full) {
		len += meta.image_size;
	}

	sbk_image_get_auth_key(&meta, otk);
        sbk_crypto_auth_init(sbuf, otk, sizeof(otk));
	sbk_crypto_cwipe(otk, sizeof(otk));

	while (len != 0) {
		uint32_t rdlen = MIN(len, sizeof(buf));

		rc = sbk_slot_read(slot, pos, buf, rdlen);
		if (rc != 0) {
			goto end;
		}

		sbk_crypto_auth_update(sbuf, buf, rdlen);

		len -= rdlen;
		pos += rdlen;
	}

	rc = sbk_crypto_auth_final(tag, sbuf);
end:
	sbk_crypto_cwipe(sbuf, sizeof(sbuf));
	SBK_LOG_DBG("Authenticity [%d]", rc);
	return rc;
}

static int sbk_image_product_dependency_verify(const struct sbk_slot *slot)
{
	SBK_ASSERT(slot);

	int rc;
	struct sbk_image_meta meta;
	uint16_t tag = SBK_IMAGE_META_TAG;
	uint32_t dcnt, mcnt;

	rc = sbk_image_get_tagdata(slot, tag, (void *)&meta, sizeof(meta));
	if (rc) {
		goto end;
	}

	dcnt = 0U;
	mcnt = 0U;
	tag = meta.product_dep_tag;

	while (true) {
		struct sbk_product_dep_info di;
		uint32_t product_hash;

		if (!sbk_image_tag_is_odd_parity(tag)) {
			break;
		}

		rc = sbk_image_get_tagdata(slot, tag, (void *)&di, sizeof(di));
		if (rc != 0) {
			goto end;
		}

		dcnt++;
		tag = di.next_tag;
		product_hash = di.product_hash;

		if (!sbk_product_hash_match(&product_hash)) {
			continue;
		}

		struct sbk_version_range range = di.vrange;
		if (!sbk_product_version_in_range(&range)) {
			continue;
		}

		mcnt++;
	}

	if ((mcnt == 0U) && (dcnt > 0)) {
		rc = -SBK_EC_EFAULT;
	}

end:
	SBK_LOG_DBG("Product dependency [%d]", rc);
	return rc;
}

static int sbk_image_image_dependency_verify(const struct sbk_slot *slot)
{
	SBK_ASSERT(slot);

	int rc;
	struct sbk_image_meta meta;
	uint16_t tag;
	uint32_t dcnt, mcnt;

	rc = sbk_image_get_tagdata(slot, SBK_IMAGE_META_TAG, (void *)&meta,
				   sizeof(meta));
	if (rc) {
		goto end;
	}

	dcnt = 0U;
	mcnt = 0U;
	tag = meta.image_dep_tag;

	while (true) {
		struct sbk_image_dep_info di;

		if (!sbk_image_tag_is_odd_parity(tag)) {
			break;
		}

		rc = sbk_image_get_tagdata(slot, tag, (void *)&di, sizeof(di));
		if (rc != 0) {
			goto end;
		}

		dcnt++;
		tag = di.next_tag;

		struct sbk_slot dslot;
		uint32_t dslt_idx = 0;
		uint32_t dep_img_address = di.image_start_address;

		while (true) {
			rc = sbk_slot_get(&dslot, dslt_idx);
			if (rc != 0) {
				rc = -SBK_EC_EFAULT;
				goto end;
			}

			rc = sbk_slot_open(&dslot);
			if (rc != 0) {
				rc = -SBK_EC_EFAULT;
				goto end;
			}

			if (sbk_slot_inrange(&dslot, dep_img_address)) {
				break;
			}

			(void)sbk_slot_close(&dslot);
			dslt_idx++;
		}

		rc = sbk_image_get_tagdata(&dslot, SBK_IMAGE_META_TAG,
					   (void *)&meta, sizeof(meta));

		if (rc != 0) {
			if (dcnt == 1) { /* override downgrade protection */
				mcnt++;
				rc = 0;
			}
			continue;
		}

		if (sbk_version_in_range(&meta.image_version, &di.vrange)) {
			mcnt++;
		}

		(void)sbk_slot_close(&dslot);
	}

	if (mcnt != dcnt) {
		rc = -SBK_EC_EFAULT;
	}

end:
	SBK_LOG_DBG("Image dependency [%d]", rc);
	return rc;
}

int sbk_image_dependency_verify(const struct sbk_slot *slot)
{
	SBK_ASSERT(slot);

	int rc;

	rc = sbk_image_product_dependency_verify(slot);
	if (rc) {
		goto end;
	}

	rc = sbk_image_image_dependency_verify(slot);
end:
	return rc;
}

int sbk_image_bootable(const struct sbk_slot *slot, unsigned long *address,
		       uint8_t *bcnt)
{
	SBK_ASSERT(slot);

	int rc;
	struct sbk_image_meta meta;

	rc = sbk_image_get_tagdata(slot, SBK_IMAGE_META_TAG, (void *)&meta,
				   sizeof(meta));
	if (rc) {
		goto end;
	}

	if (!sbk_slot_inrange(slot, meta.image_start_address)) {
		rc = -SBK_EC_EFAULT;
		goto end;
	}

	rc = sbk_image_dependency_verify(slot);
	if (rc != 0) {
		goto end;
	}

	struct sbk_image_auth auth;

	rc = sbk_image_get_tagdata(slot, SBK_IMAGE_AUTH_TAG, (void *)&auth,
				   sizeof(auth));
	if (rc != 0) {
		goto end;
	}

	rc = sbk_image_authentic(slot, &auth.fsl_fhmac[0], 32, true);
	if (rc != 0) {
		goto end;
	}

	if (sbk_image_is_confirmed(meta.image_flags)) {
		SBK_LOG_DBG("Confirmed image: reset bcnt");
		*bcnt = 0U;
	}

	*address = meta.image_start_address;
end:
	SBK_LOG_DBG("Booteable [%d]", rc);
	return rc;
}

int sbk_image_get_version(const struct sbk_slot *slot,
			  struct sbk_version *version)
{
	SBK_ASSERT(slot);

	struct sbk_image_meta meta;
	int rc;

	rc = sbk_image_get_tagdata(slot, SBK_IMAGE_META_TAG, (void *)&meta,
				   sizeof(meta));
	if (rc != 0) {
		goto end;
	}

	memcpy(version, &meta.image_version, sizeof(struct sbk_version));
end:
	return rc;
}

static int sbk_image_cipher(const struct sbk_slot *slot, unsigned long offset,
			    void *data, size_t len)
{
	const size_t cbsize = sbk_crypto_cipher_block_size();
	const size_t cssize = sbk_crypto_cipher_state_size();
	const size_t cksize = sbk_crypto_kxch_km_size();
	uint8_t dbuf[cbsize], cbuf[cbsize], est[cssize], otk[cksize];
	uint8_t *data8 = (uint8_t *)data;
	struct sbk_image_meta meta;
	int rc;

	rc = sbk_image_get_tagdata(slot, SBK_IMAGE_META_TAG, (void *)&meta,
				   sizeof(meta));
	if (rc != 0) {
		return rc;
	}

	if (offset < meta.image_offset) {
		return -SBK_EC_EINVAL;
	}

	sbk_image_get_ciph_key(&meta, otk);

	while (len != 0U) {
                uint32_t bcnt = (offset - meta.image_offset) / cbsize;
		unsigned long boff = bcnt * cbsize + meta.image_offset;
		
		rc = sbk_slot_read(slot, boff, dbuf, cbsize);
		if (rc) {
			goto end;
		}

                sbk_crypto_cipher_init(est, otk, sizeof(otk), bcnt);
		sbk_crypto_cipher(cbuf, dbuf, cbsize, est);
                while ((len != 0U) && ((offset - boff) < cbsize)) {
			(*data8) = cbuf[offset - boff];
                        data8++;
                        offset++;
                        len--;
		}

	}

end:
	sbk_crypto_cwipe(otk, sizeof(otk));
	return rc;
}

int sbk_image_read(const struct sbk_slot *slot, unsigned long off, void *data,
		   size_t len)
{
	SBK_ASSERT(slot);

	uint8_t *data8 = (uint8_t *)data;
	struct sbk_image_meta meta;
	int rc;

        rc = sbk_image_get_tagdata(slot, SBK_IMAGE_META_TAG, (void *)&meta,
				   sizeof(meta));
	if (rc != 0) {
		goto end;
	}

	if (off < meta.image_offset)	{
		size_t rdlen = SBK_MIN(len, meta.image_offset - off);
		rc = sbk_slot_read(slot, off, data8, rdlen);
		if ((rc != 0) || (rdlen == len)) {
			goto end;
		}

		off += rdlen;
		len -= rdlen;
		data8 += rdlen;
	}

	if ((sbk_image_is_encrypted(meta.image_flags)) ||
	    (sbk_slot_inrange(slot, meta.image_start_address))) {
		rc = sbk_slot_read(slot, off, data8, len);
	} else {
		rc = sbk_image_cipher(slot, off, data8, len);
	}

end:
	return rc;
}

struct ext_slot_ctx {
	const struct sbk_slot *slot;
	unsigned long eoff;
	size_t elen;
	void *edata;
};

static int ext_slot_read(const void *ctx, unsigned long off, void *data,
			 size_t len)
{
	const struct ext_slot_ctx *ectx = (const struct ext_slot_ctx *)ctx;
	uint8_t *data8 = (uint8_t *)data;
	uint8_t *edata8 = (uint8_t *)ectx->edata;
	int rc = 0;

	if (off < ectx->eoff) {
		size_t rdlen = SBK_MIN(len, ectx->eoff - off);
		rc = sbk_slot_read(ectx->slot, off, data8, rdlen);
		if (rc != 0) {
			goto end;
		}

		off += rdlen;
		len -= rdlen;
		data8 += rdlen;
	}

	memcpy(data8, edata8 + off - ectx->eoff, len);
end:
	return rc;
}

static unsigned long ext_slot_get_start_address(const void *ctx)
{
	const struct ext_slot_ctx *ectx = (const struct ext_slot_ctx *)ctx;

	return sbk_slot_get_sa(ectx->slot);
}

static size_t ext_slot_get_size(const void *ctx)
{
	const struct ext_slot_ctx *ectx = (const struct ext_slot_ctx *)ctx;

	return (size_t)(ectx->eoff + ectx->elen);
}

int sbk_image_write(const struct sbk_slot *slot, unsigned long off,
		    const void *data, size_t len)
{
	SBK_ASSERT(slot);

	/* check alignment (SBK_IMAGE_WBS is power of 2)*/
	if ((off & (SBK_IMAGE_WBS - 1)) != 0U) {
		return -SBK_EC_EINVAL;
	}

	uint8_t *data8 = (uint8_t *)data;
	struct sbk_image_meta meta;
	int rc;

	while (sbk_image_get_tagdata(slot, SBK_IMAGE_META_TAG, (void *)&meta,
	       sizeof(meta)) != 0) {
		size_t wrlen = SBK_MIN(len, SBK_IMAGE_WBS);

		rc = sbk_slot_prog(slot, off, data8, wrlen);
		if (rc != 0) {
			goto end;
		}

		len -= wrlen;
		off += wrlen;
		data8 += wrlen;

	}

	if (off < meta.image_offset) {
		size_t wrlen = SBK_MIN(len, meta.image_offset - off);

		rc = sbk_slot_prog(slot, off, data8, wrlen);
		if (rc != 0) {
			goto end;
		}

		len -= wrlen;
		off += wrlen;
		data8 += wrlen;

	}

	if ((!sbk_image_is_encrypted(meta.image_flags)) ||
	    (!sbk_slot_inrange(slot, meta.image_start_address))) {
		rc = sbk_slot_prog(slot, off, data8, len);
	} else {
		struct ext_slot_ctx eslot_ctx = {
			.eoff = off,
			.elen = len,
			.slot = slot,
			.edata = data8,
		};
		struct sbk_slot rdslot = {
			.ctx = (void *)&eslot_ctx,
			.read = ext_slot_read,
			.get_size = ext_slot_get_size,
			.get_start_address = ext_slot_get_start_address,
		};
		uint8_t buf[SBK_IMAGE_WBS];

		while (len != 0) {
			size_t wrlen = SBK_MIN(len, SBK_IMAGE_WBS);
			
			rc = sbk_image_read(&rdslot, off, buf, wrlen);
			if (rc != 0) {
				goto end;
			}

			rc = sbk_slot_prog(slot, off, buf, wrlen);
			if (rc != 0) {
				goto end;
			}
			
			len -= wrlen;
			off += wrlen;

		}
	}

end:
	return rc;
}

static int validation_read(const void *ctx, unsigned long off, void *data,
			       size_t len)
{
	const struct sbk_slot *slot = (const struct sbk_slot *)ctx;

	return sbk_image_read(slot, off, data, len);
}

static unsigned long validation_get_start_address(const void *ctx)
{
	const struct sbk_slot *slot = (const struct sbk_slot *)ctx;

	return sbk_slot_get_sa(slot);
}

static size_t validation_get_size(const void *ctx)
{
	const struct sbk_slot *slot = (const struct sbk_slot *)ctx;

	return sbk_slot_get_sz(slot);
}

int sbk_image_valid(const struct sbk_slot *slot)
{
	const struct sbk_slot rdslot = {
		.ctx = (void *)slot,
		.read = validation_read,
		.get_size = validation_get_size,
		.get_start_address = validation_get_start_address,
	};
	struct sbk_image_auth auth;
        int rc;

        rc = sbk_image_dependency_verify(&rdslot);
	if (rc != 0) {
	        goto end;
	}

	rc = sbk_image_get_tagdata(&rdslot, SBK_IMAGE_AUTH_TAG, (void *)&auth,
                                   sizeof(auth));
	if (rc != 0) {
		goto end;
	}

	rc = sbk_image_authentic(&rdslot, &auth.upd_fhmac[0], 32, true);

end:
        return rc;
}

