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

bool sbk_image_hmac_ok(const struct sbk_slot *slot,
		       const struct sbk_image_meta *meta,
		       const uint8_t *tag, size_t tlen)
{
	bool rv = false;
	uint32_t pos, len;
	uint8_t otk[sbk_crypto_kxch_km_size()];
	uint8_t sbuf[sbk_crypto_auth_state_size()];
	uint8_t buf[64];
     
        pos = sizeof(struct sbk_image_auth);
	len = meta->image_offset + meta->image_size - pos;
	sbk_image_get_auth_key(meta, otk);
        sbk_crypto_auth_init(sbuf, otk, sizeof(otk));
	sbk_crypto_cwipe(otk, sizeof(otk));

	while (len != 0) {
		uint32_t rdlen = MIN(len, sizeof(buf));

		if (sbk_slot_read(slot, pos, buf, rdlen) != 0) {
			goto end;
		}

		sbk_crypto_auth_update(sbuf, buf, rdlen);
		len -= rdlen;
		pos += rdlen;
	}

	if (sbk_crypto_auth_final(tag, sbuf) == 0) {
		rv = true;
	}
end:
	sbk_crypto_cwipe(sbuf, sizeof(sbuf));
	SBK_LOG_DBG("Authenticity [%s]", rv ? "OK" : "NOK");
	return rv;
}

static bool sbk_image_product_dependency_ok(const struct sbk_slot *slot,
					    const struct sbk_image_meta *meta)
{
	bool rv = false;
	uint16_t tag = meta->product_dep_tag;
	uint32_t dcnt = 0U, mcnt = 0U;

	while (true) {
		struct sbk_product_dep_info di;
		uint32_t product_hash;

		if (sbk_image_get_tagdata(slot, tag, (void *)&di, sizeof(di)) != 0) {
			break;
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
		goto end;
	}

	rv = true;

end:
	SBK_LOG_DBG("Product dependency [%s]", rv ? "OK" : "NOK");
	return rv;
}

static bool slot_dep_ok(const struct sbk_slot *slot, uint32_t di_address,
			struct sbk_version_range *range)
{
	struct sbk_image_meta meta;
	unsigned long address;
		
	if (sbk_image_get_tagdata(slot, SBK_IMAGE_META_TAG,
				  (void *)&meta, sizeof(meta)) != 0) {
		return false;

	}

	if (sbk_slot_address(slot, 0U, &address) != 0) {
		return false;
	}

	if (di_address != (meta.image_offset + address)) {
		return false;
	}

	if (!sbk_version_in_range(&meta.image_version, range)) {
		return false;
	}

	SBK_LOG_DBG("slot dep OK: %d.%d-%d in %d.%d-%d to %d.%d-%d", 
		    meta.image_version.major, meta.image_version.minor, meta.image_version.revision,
		    range->min_version.major, range->min_version.minor, range->min_version.revision,
		    range->max_version.major, range->max_version.minor, range->max_version.revision);
	return true;
}

static bool sbk_image_image_dependency_ok(const struct sbk_slot *slot,
					  const struct sbk_image_meta *meta)
{
	bool rv = false;
	uint16_t tag = meta->image_dep_tag;;
	uint32_t dcnt= 0U, mcnt = 0U;

	while (true) {
		struct sbk_image_dep_info di;

		if (sbk_image_get_tagdata(slot, tag, (void *)&di, sizeof(di)) != 0) {
			break;
		}

		dcnt++;
		tag = di.next_tag;

		struct sbk_slot dslot;
		uint32_t dslt_idx = 0;
		uint32_t dep_addr = di.image_start_address;

		while (sbk_slot_get(&dslot, dslt_idx) == 0) {
			dslt_idx++;

			if (sbk_slot_open(&dslot) != 0) {
				continue;
			}

			if (slot_dep_ok(&dslot, dep_addr, &di.vrange)) {
				mcnt++;
			}

			(void)sbk_slot_close(&dslot);
		}

	}

	if (mcnt != dcnt) {
		goto end;
	}

	rv = true;
end:
	SBK_LOG_DBG("Image dependency [%s]", rv ? "OK" : "NOK");
	return rv;
}

bool sbk_image_dependency_ok(const struct sbk_slot *slot,
			     const struct sbk_image_meta *meta)
{
	bool rv = false;

	if (!sbk_image_product_dependency_ok(slot, meta)) {
		goto end;
	}
	
	if (!sbk_image_image_dependency_ok(slot, meta)) {
		goto end;
	}

	rv = true;
end:
	return rv;
}

int sbk_image_bootable(const struct sbk_slot *slot, unsigned long *address,
		       uint8_t *bcnt)
{
	int rc;
	struct sbk_image_meta meta;
	unsigned long saddr;

	rc = sbk_image_get_tagdata(slot, SBK_IMAGE_META_TAG, (void *)&meta,
				   sizeof(meta));
	if (rc) {
		goto end;
	}

	rc = sbk_slot_address(slot, 0U, &saddr);
	if (rc) {
		goto end;
	}

	if (saddr != (meta.image_start_address - meta.image_offset)) {
		rc = -SBK_EC_EFAULT;
		goto end;
	}

	if (!sbk_image_product_dependency_ok(slot, &meta)) {
		rc = -SBK_EC_EFAULT;
		goto end;
	}

	if (!sbk_image_image_dependency_ok(slot, &meta)) {
		rc = -SBK_EC_EFAULT;
		goto end;
	}

	struct sbk_image_auth auth;

	rc = sbk_image_get_tagdata(slot, SBK_IMAGE_AUTH_TAG, (void *)&auth,
				   sizeof(auth));
	if (rc != 0) {
		goto end;
	}

	if (!sbk_image_hmac_ok(slot, &meta, &auth.fsl_fhmac[0], 32)) {
		rc = -SBK_EC_EFAULT;
		goto end;
	};

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
	uint8_t *data8 = (uint8_t *)data;
	struct sbk_image_meta meta;
	unsigned long saddr;
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

	if ((!sbk_image_is_encrypted(meta.image_flags)) ||
	    (sbk_slot_address(slot, 0U, &saddr) != 0) ||
	    (saddr != meta.image_start_address - meta.image_offset)) {
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

static int ext_slot_address(const void *ctx, unsigned long off,
				      unsigned long *address)
{
	const struct ext_slot_ctx *ectx = (const struct ext_slot_ctx *)ctx;

	return sbk_slot_address(ectx->slot, off, address);
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

	unsigned long saddr;

	if ((!sbk_image_is_encrypted(meta.image_flags)) ||
	    (sbk_slot_address(slot, off, &saddr) != 0) ||
	    (saddr != meta.image_start_address - meta.image_offset)) {
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
			.size = off + len, 
			.read = ext_slot_read,
			.address = ext_slot_address,
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

static int validation_address(const void *ctx, unsigned long off,
					unsigned long *address)
{
	const struct sbk_slot *slot = (const struct sbk_slot *)ctx;

	return sbk_slot_address(slot, off, address);
}

int sbk_image_valid(const struct sbk_slot *slot)
{
	const struct sbk_slot rdslot = {
		.ctx = (void *)slot,
		.size = slot->size,
		.read = validation_read,
		.address = validation_address,
	};
	struct sbk_image_auth auth;
	struct sbk_image_meta meta;
	int rc;

	rc = sbk_image_get_tagdata(&rdslot, SBK_IMAGE_META_TAG, (void *)&meta,
				   sizeof(meta));
	if (rc) {
		goto end;
	}

	if (!sbk_image_dependency_ok(&rdslot, &meta)) {
		rc = -SBK_EC_EFAULT;
		goto end;
	}

	rc = sbk_image_get_tagdata(&rdslot, SBK_IMAGE_AUTH_TAG, (void *)&auth,
				   sizeof(auth));
	if (rc != 0) {
		goto end;
	}

	if (!sbk_image_hmac_ok(&rdslot, &meta, &auth.upd_fhmac[0], 32)) {
		rc = -SBK_EC_EFAULT;
		goto end;
	};

end:
	return rc;
}

int sbk_image_hdr_valid(void *data, size_t len)
{
	struct ext_slot_ctx eslot_ctx = {
		.eoff = 0U,
		.elen = len,
		.slot = NULL,
		.edata = data,
	};
	struct sbk_slot rdslot = {
		.ctx = (void *)&eslot_ctx,
		.size = len, 
		.read = ext_slot_read,
		.address = NULL,
	};
	struct sbk_image_auth auth;
	struct sbk_image_meta meta;
	int rc;

	rc = sbk_image_get_tagdata(&rdslot, SBK_IMAGE_META_TAG, (void *)&meta,
				   sizeof(meta));
	if (rc) {
		goto end;
	}

	if (!sbk_image_dependency_ok(&rdslot, &meta)) {
		rc = -SBK_EC_EFAULT;
		goto end;
	}

	rc = sbk_image_get_tagdata(&rdslot, SBK_IMAGE_AUTH_TAG, (void *)&auth,
				   sizeof(auth));
	if (rc != 0) {
		goto end;
	}

	meta.image_size = 0U;
	if (!sbk_image_hmac_ok(&rdslot, &meta, &auth.upd_shmac[0], 32)) {
		rc = -SBK_EC_EFAULT;
		goto end;
	};

end:
	return rc;
}
// int sbk_image_check_hdr(const struct sbk_slot *slot)
// {
// 	return sbk_image_check_general(slot, false);
// }
