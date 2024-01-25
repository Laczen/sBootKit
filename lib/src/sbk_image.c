/*
 * Copyright (c) 2023 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stddef.h>
#include <string.h>
#include "sbk/sbk_crypto.h"
#include "sbk/sbk_slot.h"
#include "sbk/sbk_tlv.h"
#include "sbk/sbk_image.h"
#include "sbk/sbk_log.h"

static int sbk_crypto_mem_read(const void *ctx, uint32_t off, void *data,
			       size_t len)
{
	const uint8_t *src = (const uint8_t *)ctx;

	memcpy(data, src + off, len);
	return 0;
}

struct sbk_crypto_slot_ctx {
	const struct sbk_slot *slot;
	uint32_t soff;
};

static int sbk_crypto_slot_read(const void *ctx, uint32_t off, void *data,
				size_t len)
{
	const struct sbk_crypto_slot_ctx *sctx =
		(const struct sbk_crypto_slot_ctx *)ctx;

	return sbk_slot_read(sctx->slot, sctx->soff + off, data, len);
}

#ifdef SBK_PRODUCT_DEP
static bool sbk_image_pdep_ok(const struct sbk_slot *slot, uint16_t tag)
{
	struct sbk_tlv_product_data pdata;
	bool rv = false;

	if (sbk_tlv_get_product_data(&data) != 0) {
		rv = true;
		goto end;
	}

	struct sbk_tlv_product_dep_info pdi;

	while (true) {
		if ((sbk_tlv_get_data(slot, tag, &pdi, pdisz) != 0) ||
		    (tag == SBK_IMAGE_LEND_TAG)) {
			break;
		}

		tag = pdi.next_tag;

		if (sbk_crypto_compare(pdi.guid, pdata.guid, SBK_PRODUCT_GUID_SIZE) != 0) {
			continue;
		}

		if (sbk_version_in_range(&pdata.version, &pdi.vrange)) {
			rv = true;
			break;
		}
	}

end:
	SBK_LOG_DBG("product %s", rv ? "ok" : "nok");
	return rv;
}
#else
static bool sbk_image_pdep_ok(const struct sbk_slot *slot, uint16_t tag)
{
	return true;
}
#endif

#ifdef CONFIG_SBK_IMAGE_DEP
static bool sbk_image_idep_ok(const struct sbk_slot *slot, uint16_t tag,
			      bool (*depcheck)(const struct sbk_slot *slot,
					       uint32_t di_address,
					       struct sbk_version_range *range))
{
	uint32_t dcnt = 0U, mcnt = 0U;
	bool rv = false;

	while (true) {
		struct sbk_tlv_image_dep_info idi;
		const size_t idisz = sizeof(idi);

		if ((sbk_tlv_get_data(slot, tag, &idi, idisz) != 0) ||
		    (tag == SBK_IMAGE_LEND_TAG)) {
			break;
		}

		dcnt++;
		tag = idi.next_tag;

		uint32_t dep_addr = idi.image_start_address;
		struct sbk_slot dslot;
		uint8_t dslot_no = 0U;

		while (true) {
			if (sbk_open_image_slot(&dslot, dslot_no) != 0) {
				break;
			}

			if (depcheck(&dslot, dep_addr, &idi.vrange)) {
				mcnt++;
			}

			dslot_no++;
			(void)sbk_slot_close(&dslot);
		}
	}

	if (mcnt == dcnt) {
		rv = true;
	}

	SBK_LOG_DBG("image %s", rv ? "dependency ok" : "dependency error");
	return rv;
}
#else
static bool sbk_image_idep_ok(const struct sbk_slot *slot, uint16_t tag,
			      bool (*depcheck)(const struct sbk_slot *slot,
					       uint32_t di_address,
					       struct sbk_version_range *range))
{
	return true;
}
#endif

static bool sbk_image_info_found(const struct sbk_slot *slot,
				 struct sbk_tlv_image_info *tlv_info)
{
	const uint16_t tag = SBK_IMAGE_INFO_TAG;
	const size_t isz = sizeof(struct sbk_tlv_image_info);
	int rc = sbk_tlv_get_data(slot, tag, tlv_info, isz);

	SBK_LOG_DBG("image info %s", rc == 0 ? "present" : "missing");
	return rc == 0 ? true : false;
}

static bool sbk_image_local_confirmed(const struct sbk_slot *slot,
				      const struct sbk_tlv_image_info *tlv_info)
{
	uint8_t buf[sizeof(SBK_IMAGE_STATE_SCONF_MAGIC) - 1];
	uint32_t rdoff = tlv_info->image_offset - sizeof(buf);
	bool rv = false;

	if (sbk_slot_read(slot, rdoff, &buf, sizeof(buf)) != 0) {
		goto end;
	}

	if (memcmp(buf, SBK_IMAGE_STATE_SCONF_MAGIC, sizeof(buf)) == 0) {
		rv = true;
	}

end:
	SBK_LOG_DBG("%s", rv ? "local confirmed" : "local unconfirmed");
	return rv;
}

static bool sbk_image_address(const struct sbk_slot *slot, uint32_t *address)
{
	return sbk_slot_ioctl(slot, SBK_SLOT_IOCTL_GET_ADDRESS, address,
			      sizeof(uint32_t)) == 0;
}

static bool sbk_image_in_exe_slot(const struct sbk_slot *slot,
				  const struct sbk_tlv_image_info *tlv_info)
{
	uint32_t address = tlv_info->image_offset;
	bool rv = false;

	if (!sbk_image_address(slot, &address)) {
		goto end;
	}

	if (address != tlv_info->image_start_address) {
		goto end;
	}

	rv = true;
end:
	return rv;
}

static void sbk_image_init_info(const struct sbk_slot *slot,
				struct sbk_image_info *info,
				struct sbk_tlv_image_info *tlv_info)
{
	if (sbk_image_info_found(slot, tlv_info)) {
		SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_STATE_IINF);
	} else {
		return;
	}

	info->image_sequence_number = tlv_info->image_sequence_number;
	info->image_start_address = tlv_info->image_start_address;

	if (SBK_IMAGE_FLAG_ISSET(tlv_info->image_flags, SBK_IMAGE_FLAG_CONF)) {
		SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_FLAG_CONF);
	}

	if (sbk_image_local_confirmed(slot, tlv_info)) {
		SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_FLAG_CONF);
	}

	if (sbk_image_in_exe_slot(slot, tlv_info)) {
		SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_STATE_INRS);
	}
}

static bool sbk_image_hash_ok(const struct sbk_slot *slot,
			      const struct sbk_tlv_image_info *tlv_info)
{
	const struct sbk_crypto_slot_ctx sctx = {
		.slot = slot,
		.soff = tlv_info->image_offset,
	};
	const struct sbk_crypto_read_ctx rdctx = {
		.read = sbk_crypto_slot_read,
		.ctx = (void *)&sctx,
	};
	const struct sbk_crypto_hash_ctx hctx = {
		.hash = (void *)&tlv_info->image_hash[0],
		.hash_size = SBK_IMAGE_HASH_SIZE,
		.chunk_size = 512,
	};
	bool rv = false;

	if (sbk_crypto_hash_vrfy(&hctx, &rdctx, tlv_info->image_size) == 0) {
		rv = true;
	}

	SBK_LOG_DBG("hash %s", rv ? "valid" : "invalid");
	return rv;
}

/* secure first stage loader (sFSL) specific routines */
static bool sbk_image_sfsl_sign_ok(const struct sbk_slot *slot,
				   const struct sbk_tlv_image_sfsl_auth *auth)
{
	const uint16_t tag = SBK_IMAGE_SFSL_TAG;
	const struct sbk_crypto_sigp256_ctx p256_ctx = {
		.pubkey = (void *)&auth->pubkey[0],
		.pubkey_size = SBK_IMAGE_PUBK_SIZE,
		.signature = (void *)&auth->sign[0],
		.signature_size = SBK_IMAGE_SIGN_SIZE,
	};
	const struct sbk_crypto_slot_ctx sctx = {
		.slot = slot,
		.soff = 0U,
	};
	const struct sbk_crypto_read_ctx rdctx = {
		.read = sbk_crypto_slot_read,
		.ctx = (void *)&sctx,
	};
	struct sbk_tlv_erhdr erhdr = {
		.pos = 0U,
		.rhdr.len = 0U,
	};
	bool rv = false;

	if (sbk_tlv_get_erhdr(slot, tag, &erhdr) != 0) {
		goto end;
	}

	if (sbk_crypto_sigp256_vrfy(&p256_ctx, &rdctx, erhdr.pos) == 0) {
		rv = true;
	}

end:
	return rv;
}

static bool sbk_image_sfsl_has_pubkey_info(const struct sbk_slot *slot)
{
	const uint16_t tag = SBK_IMAGE_PUBK_TAG;
	struct sbk_tlv_erhdr erhdr = {
		.pos = 0U,
		.rhdr.len = 0U,
	};
	bool rv = false;

	if (sbk_tlv_get_erhdr(slot, tag, &erhdr) == 0) {
		rv = true;
	}

	return rv;
}

static bool sbk_image_sfsl_pubkey_ok(const struct sbk_slot *slot,
				     const struct sbk_tlv_image_sfsl_auth *auth)
{
	const uint16_t tag = SBK_IMAGE_PUBK_TAG;
	struct sbk_tlv_erhdr erhdr = {
		.pos = 0U,
		.rhdr.len = 0U,
	};
	uint8_t hash[SBK_IMAGE_HASH_SIZE];
	bool rv = false;

	if (sbk_tlv_get_erhdr(slot, tag, &erhdr) != 0) {
		goto end;
	}

	erhdr.rhdr.len -= sizeof(struct sbk_tlv_rhdr);
	erhdr.pos += sizeof(struct sbk_tlv_rhdr);

	while (erhdr.rhdr.len != 0) {
		const size_t hsize = SBK_IMAGE_HASH_SIZE;
		const struct sbk_crypto_read_ctx read_ctx = {
			.read = sbk_crypto_mem_read,
			.ctx = (void *)&auth->pubkey[0],
		};
		const struct sbk_crypto_hash_ctx hash_ctx = {
			.hash = (void *)&hash[0],
			.hash_size = hsize,
		};
		const size_t pksize = SBK_IMAGE_PUBK_SIZE;

		if (sbk_slot_read(slot, erhdr.pos, hash, hsize) != 0) {
			break;
		}

		if (sbk_crypto_hash_vrfy(&hash_ctx, &read_ctx, pksize) == 0) {
			rv = true;
			break;
		}

		erhdr.rhdr.len -= SBK_IMAGE_HASH_SIZE;
		erhdr.pos += SBK_IMAGE_HASH_SIZE;
		if (erhdr.rhdr.len < SBK_IMAGE_HASH_SIZE) {
			break;
		}
	}

end:
	SBK_LOG_DBG("pubkey %s", rv ? "valid" : "invalid");
	return rv;
}

bool sbk_image_sfsl_auth_ok(const struct sbk_slot *slot)
{
	const uint16_t tag = SBK_IMAGE_SFSL_TAG;
	struct sbk_tlv_image_sfsl_auth auth;
	struct sbk_slot sldr_slot;
	bool rv = false;

	if (sbk_tlv_get_data(slot, tag, &auth, sizeof(auth)) != 0) {
		goto end;
	}

	if (sbk_open_sldr_slot(&sldr_slot) != 0) {
		goto end;
	}

	if ((sbk_image_sfsl_pubkey_ok(&sldr_slot, &auth)) ||
	    ((!sbk_image_sfsl_has_pubkey_info(&sldr_slot)) &&
	     (sbk_image_sfsl_pubkey_ok(slot, &auth)))) {
		/* accept pubkey from loader slot or from exe slot if loader
		 * does not contain pubkey info
		 */
		rv = sbk_image_sfsl_sign_ok(slot, &auth);
	}

end:
	SBK_LOG_DBG("auth %s", rv ? "valid" : "invalid");
	return rv;
}

#ifdef CONFIG_SBK_IMAGE_DEP
static bool sfsl_idep_ok(const struct sbk_slot *slot, uint32_t di_address,
			 struct sbk_version_range *range)
{
	const uint16_t tag = SBK_IMAGE_INFO_TAG;
	struct sbk_tlv_image_info tlv_info;
	uint32_t address;
	bool rv = false;

	if (sbk_tlv_get_data(slot, tag, &tlv_info, sizeof(tlv_info)) != 0) {
		goto end;
	}

	if (tlv_info.idep_tag != SBK_IMAGE_LEND_TAG) {
		/* image dependency stops after one image */
		goto end;
	}

	if (!sbk_version_in_range(&tlv_info.image_version, range)) {
		goto end;
	}

	address = tlv_info.image_offset;
	if (sbk_image_address(slot, &address) != 0) {
		goto end;
	}

	if (di_address != address) {
		goto end;
	}

	if (!sbk_image_sfsl_auth_ok(slot)) {
		goto end;
	}

	if ((tlv_info.pdep_tag != SBK_IMAGE_LEND_TAG) &&
	    (!sbk_image_pdep_ok(slot, tlv_info.pdep_tag))) {
		goto end;
	}

	if (!sbk_image_hash_ok(slot, &tlv_info)) {
		goto end;
	}

	rv = true;
end:
	return rv;
}
#else
static bool sfsl_idep_ok(const struct sbk_slot *slot, uint32_t di_address,
			 struct sbk_version_range *range)
{
	return true;
}
#endif

void sbk_image_sfsl_state(const struct sbk_slot *slot,
			  struct sbk_image_info *info)
{
	struct sbk_tlv_image_info tlv_info;

	if (sbk_image_sfsl_auth_ok(slot)) {
		SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_STATE_BAUT);
	}

	sbk_image_init_info(slot, info, &tlv_info);

	if (tlv_info.idep_tag == SBK_IMAGE_LEND_TAG) {
		SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_STATE_IDEP);
	} else if (sbk_image_idep_ok(slot, tlv_info.idep_tag, sfsl_idep_ok)) {
		SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_STATE_IDEP);
	}

	if (tlv_info.pdep_tag == SBK_IMAGE_LEND_TAG) {
		SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_STATE_PDEP);

	} else if (sbk_image_pdep_ok(slot, tlv_info.pdep_tag)) {
		SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_STATE_PDEP);
	}

	if (sbk_image_hash_ok(slot, &tlv_info)) {
		SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_STATE_VHSH);
	}
}

/* secure loader (sLDR) specific routines */
static void sbk_image_sldr_hmac_key(const uint8_t *salt, size_t salt_size,
				    uint8_t *otk, size_t otk_size)
{
	const struct sbk_key *privkey = sbk_get_private_key();

	if (privkey == NULL) {
		return;
	}

	uint8_t context[] = SBK_IMAGE_HMAC_CONTEXT;
	struct sbk_crypto_kxch_ctx kxctx = {
		.pkey = privkey->key,
		.pkey_size = privkey->key_size,
		.salt = salt,
		.salt_size = salt_size,
		.context = context,
		.context_size = sizeof(context) - 1,
	};

	sbk_crypto_kxch(&kxctx, otk, otk_size);
	sbk_crypto_cwipe(context, sizeof(context));
	sbk_crypto_cwipe(&kxctx, sizeof(kxctx));
}

static void sbk_image_sldr_ciph_key(const uint8_t *salt, size_t salt_size,
				    uint8_t *otk, size_t otk_size)
{
	const struct sbk_key *privkey = sbk_get_private_key();

	if (privkey == NULL) {
		return;
	}

	uint8_t context[] = SBK_IMAGE_CIPH_CONTEXT;
	struct sbk_crypto_kxch_ctx kxctx = {
		.pkey = privkey->key,
		.pkey_size = privkey->key_size,
		.salt = salt,
		.salt_size = salt_size,
		.context = context,
		.context_size = sizeof(context) - 1,
	};

	sbk_crypto_kxch(&kxctx, otk, otk_size);
	sbk_crypto_cwipe(context, sizeof(context));
	sbk_crypto_cwipe(&kxctx, sizeof(kxctx));
}

static bool sbk_image_sldr_hmac_ok(const struct sbk_slot *slot,
				   const struct sbk_tlv_image_sldr_auth *auth,
				   uint8_t *otk, size_t otk_size)
{
	const uint16_t tag = SBK_IMAGE_SLDR_TAG;
	const struct sbk_crypto_hmac_ctx hctx = {
		.key = (void *)otk,
		.key_size = otk_size,
		.hmac = (void *)&auth->hmac[0],
		.hmac_size = SBK_IMAGE_HMAC_SIZE,
	};
	const struct sbk_crypto_slot_ctx sctx = {
		.slot = slot,
		.soff = 0U,
	};
	const struct sbk_crypto_read_ctx rdctx = {
		.read = sbk_crypto_slot_read,
		.ctx = (void *)&sctx,
	};
	struct sbk_tlv_erhdr erhdr;
	bool rv = false;

	if (sbk_tlv_get_erhdr(slot, tag, &erhdr) != 0) {
		goto end;
	}

	if (sbk_crypto_hmac_vrfy(&hctx, &rdctx, erhdr.pos) == 0) {
		rv = true;
	}

end:
	return rv;
}

bool sbk_image_sldr_auth_ok(const struct sbk_slot *slot)
{
	const uint16_t tag = SBK_IMAGE_SLDR_TAG;
	struct sbk_tlv_image_sldr_auth auth;
	uint8_t otk[SBK_IMAGE_HMAC_KEY_SIZE];
	bool rv = false;

	if (sbk_tlv_get_data(slot, tag, &auth, sizeof(auth)) != 0) {
		goto end;
	}

	sbk_image_sldr_hmac_key(&auth.salt[0], SBK_IMAGE_SALT_SIZE, otk,
				sizeof(otk));

	rv = sbk_image_sldr_hmac_ok(slot, &auth, otk, sizeof(otk));
	sbk_crypto_cwipe(otk, sizeof(otk));
end:
	SBK_LOG_DBG("auth %s", rv ? "valid" : "invalid");
	return rv;
}

static int sbk_image_ciphered_read(const struct sbk_crypto_slot_ctx *sctx,
				   uint32_t off, void *data, size_t len)
{
	const uint16_t tag = SBK_IMAGE_SLDR_TAG;
	struct sbk_tlv_image_sldr_auth auth;
	uint8_t otk[sbk_crypto_ciphered_read_km_size()];
	uint8_t *data8 = (uint8_t *)data;
	int rc;

	if (off < sctx->soff) {
		size_t rdlen = SBK_MIN(len, sctx->soff - off);

		rc = sbk_slot_read(sctx->slot, off, data8, rdlen);
		len -= rdlen;
		if ((rc != 0) || (len == 0U)) {
			goto end;
		}

		off += rdlen;
		data8 += rdlen;
	}

	rc = sbk_tlv_get_data(sctx->slot, tag, &auth, sizeof(auth));
	if (rc != 0) {
		goto end;
	}

	sbk_image_sldr_ciph_key(&auth.salt[0], SBK_IMAGE_SALT_SIZE, otk,
				sizeof(otk));

	const struct sbk_crypto_read_ctx rdctx = {
		.ctx = sctx,
		.read = sbk_crypto_slot_read,
	};
	const struct sbk_crypto_ciphered_read_ctx crdctx = {
		.read_ctx = &rdctx,
		.key = otk,
		.key_size = sizeof(otk),
	};

	rc = sbk_crypto_ciphered_read(&crdctx, off - sctx->soff, data8, len);
end:
	return rc;
}

int sbk_image_read(const struct sbk_slot *slot, uint32_t off, void *data,
		   size_t len)
{
	const uint16_t tag = SBK_IMAGE_INFO_TAG;
	struct sbk_tlv_image_info tlv_info;
	int rc;

	rc = sbk_tlv_get_data(slot, tag, &tlv_info, sizeof(tlv_info));
	if (rc != 0) {
		goto end;
	}

	if ((SBK_IMAGE_FLAG_ISSET(tlv_info.image_flags, SBK_IMAGE_FLAG_CIPH)) &&
	    (sbk_image_in_exe_slot(slot, &tlv_info))) {
		const struct sbk_crypto_slot_ctx sctx = {
			.slot = slot,
			.soff = tlv_info.image_offset,
		};

		rc = sbk_image_ciphered_read(&sctx, off, data, len);
	} else {
		rc = sbk_slot_read(slot, off, data, len);
	}

end:
	return rc;
}

static int sbk_image_read_decrypted(const struct sbk_slot *slot, uint32_t off,
				    void *data, size_t len)
{
	const uint16_t tag = SBK_IMAGE_INFO_TAG;
	struct sbk_tlv_image_info tlv_info;
	int rc;

	rc = sbk_tlv_get_data(slot, tag, &tlv_info, sizeof(tlv_info));
	if (rc != 0) {
		goto end;
	}

	if ((SBK_IMAGE_FLAG_ISSET(tlv_info.image_flags, SBK_IMAGE_FLAG_CIPH)) &&
	    (!sbk_image_in_exe_slot(slot, &tlv_info))) {
		const struct sbk_crypto_slot_ctx sctx = {
			.slot = slot,
			.soff = tlv_info.image_offset,
		};

		rc = sbk_image_ciphered_read(&sctx, off, data, len);
	} else {
		rc = sbk_slot_read(slot, off, data, len);
	}

end:
	return rc;
}
#ifdef CONFIG_SBK_IMAGE_DEP
static bool sldr_idep_ok(const struct sbk_slot *slot, uint32_t di_address,
			 struct sbk_version_range *range)
{
	const uint16_t tag = SBK_IMAGE_INFO_TAG;
	struct sbk_tlv_image_info tlv_info;
	uint32_t address;
	bool rv = false;

	if (sbk_tlv_get_data(slot, tag, &tlv_info, sizeof(tlv_info)) != 0) {
		goto end;
	}

	if (tlv_info.idep_tag != SBK_IMAGE_LEND_TAG) {
		/* image dependency stops after one image */
		goto end;
	}

	if (!sbk_version_in_range(&tlv_info.image_version, range)) {
		goto end;
	}

	address = tlv_info.image_offset;
	if (sbk_image_address(slot, &address) != 0) {
		goto end;
	}

	if (di_address != address) {
		goto end;
	}

	if ((tlv_info.pdep_tag != SBK_IMAGE_LEND_TAG) &&
	    (!sbk_image_pdep_ok(slot, tlv_info.pdep_tag))) {
		goto end;
	}

	if (!sbk_image_hash_ok(slot, &tlv_info)) {
		goto end;
	}

	rv = true;
end:
	return rv;
}
#else
static bool sldr_idep_ok(const struct sbk_slot *slot, uint32_t di_address,
			 struct sbk_version_range *range)
{
	return true;
}
#endif

static int sbk_dslot_read(const void *ctx, uint32_t off, void *data, size_t len)
{
	const struct sbk_slot *slot = (const struct sbk_slot *)ctx;

	return sbk_image_read_decrypted(slot, off, data, len);
}

static int sbk_dslot_ioctl(const void *ctx, enum sbk_slot_ioctl_cmd cmd,
			   void *data, size_t len)
{
	const struct sbk_slot *slot = (const struct sbk_slot *)ctx;

	return sbk_slot_ioctl(slot, cmd, data, len);
}

void sbk_image_sldr_state(const struct sbk_slot *slot,
			  struct sbk_image_info *info)
{
	struct sbk_tlv_image_info tlv_info;

	if (sbk_image_sldr_auth_ok(slot)) {
		SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_STATE_LAUT);
	}

	sbk_image_init_info(slot, info, &tlv_info);

	if (tlv_info.idep_tag == SBK_IMAGE_LEND_TAG) {
		SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_STATE_IDEP);
	} else if (sbk_image_idep_ok(slot, tlv_info.idep_tag, sldr_idep_ok)) {
		SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_STATE_IDEP);
	}

	if (tlv_info.pdep_tag == SBK_IMAGE_LEND_TAG) {
		SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_STATE_PDEP);

	} else if (sbk_image_pdep_ok(slot, tlv_info.pdep_tag)) {
		SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_STATE_PDEP);
	}

	if (!SBK_IMAGE_FLAG_ISSET(tlv_info.image_flags, SBK_IMAGE_FLAG_CIPH)) {
		if (sbk_image_hash_ok(slot, &tlv_info)) {
			SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_STATE_VHSH);
		}
	} else {
		struct sbk_slot cslot = {
			.ctx = (void *)slot,
			.read = sbk_dslot_read,
			.ioctl = sbk_dslot_ioctl,
		};

		if (sbk_image_hash_ok(&cslot, &tlv_info)) {
			SBK_IMAGE_STATE_SET(info->state, SBK_IMAGE_STATE_VHSH);
		}
	}
}

bool sbk_image_sfsl_swap_needed(uint32_t *idx)
{
	bool rv = false;
	struct sbk_slot upd, img;
	struct sbk_tlv_image_info img_tlv_info, upd_tlv_info;

	size_t sltcnt = 0;

	while (sbk_open_update_slot(&upd, sltcnt) == 0) {
		sltcnt++;
		(void)sbk_slot_close(&upd);
	}

	while ((sltcnt != 0) && (!rv)) {
		sltcnt--;

		if (sbk_open_update_slot(&upd, sltcnt) != 0) {
			continue;
		}

		if (!sbk_image_info_found(&upd, &upd_tlv_info)) {
			sbk_slot_close(&upd);
			continue;
		}

		(void)sbk_slot_close(&upd);
		if (sbk_open_image_slot(&img, sltcnt) != 0) {
			continue;
		}

		if ((!sbk_image_info_found(&img, &img_tlv_info)) ||
		    (sbk_image_in_exe_slot(&img, &upd_tlv_info) &&
		     (upd_tlv_info.image_sequence_number >
		      img_tlv_info.image_sequence_number))) {
			*idx = sltcnt;
			rv = true;
		}

		(void)sbk_slot_close(&img);

	}

	SBK_LOG_DBG("%s", rv ? "Need to swap image" : "");
	return rv;
}

bool sbk_image_sfsl_swap(uint32_t idx)
{
	return false;
}

// struct sbk_boot_slot_ctx {
// 	const struct sbk_slot *slt;
// 	uint32_t split_pos;
// 	uint32_t split_jmp;
// };

// int boot_slot_read(const void *ctx, uint32_t off, void *data, size_t len)
// {
// 	struct sbk_boot_slot_ctx *bsctx = (struct sbk_boot_slot_ctx *)ctx;
// 	uint8_t *data8 = (uint8_t *)data;
// 	int rc;

// 	if (bsctx->split_pos == 0U) {
// 		/* setup the split slot (authentication data is after
// 		 * image) */
// 		const size_t meta_sz = sizeof(struct sbk_image_meta);
// 		struct sbk_image_record_info info = {.pos = 0U, .size = 0U};
// 		struct sbk_image_meta meta;

// 		rc = sbk_image_get_record_info(bsctx->slt, SBK_IMAGE_AUTH_TAG,
// 					       &info);
// 		if (rc != 0) {
// 			goto end;
// 		}

// 		rc = sbk_image_get_tagdata(bsctx->slt, SBK_IMAGE_META_TAG, &meta,
// 					   meta_sz);
// 		if (rc != 0) {
// 			goto end;
// 		}

// 		bsctx->split_pos = info.pos + info.size;
// 		bsctx->split_jmp = meta.image_offset + meta.image_size;
// 	}

// 	if (off < bsctx->split_pos) {
// 		size_t rdlen = SBK_MIN(len, bsctx->split_pos - off);

// 		rc = sbk_slot_read(bsctx->slt, off + bsctx->split_jmp, data8,
// 				   rdlen);

// 		if (rc != 0) {
// 			goto end;
// 		}

// 		data8 += rdlen;
// 		off += rdlen;
// 		len -= rdlen;
// 	}

// 	if (len != 0U) {
// 		rc = sbk_slot_read(bsctx->slt, off, data8, len);
// 	}

// end:
// 	return rc;
// }

// int boot_slot_size(const void *ctx, size_t *size)
// {
// 	struct sbk_boot_slot_ctx *bsctx = (struct sbk_boot_slot_ctx *)ctx;

// 	return sbk_slot_size(bsctx->slt, size);
// }

// int boot_slot_address(const void *ctx, uint32_t *addr)
// {
// 	struct sbk_boot_slot_ctx *bsctx = (struct sbk_boot_slot_ctx *)ctx;

// 	return sbk_slot_address(bsctx->slt, addr);
// }

// bool sbk_image_can_run(const struct sbk_slot *slt, struct sbk_image_state *st)
// {
// 	struct sbk_boot_slot_ctx bsctx = {
// 		.slt = slt, .split_pos = 0U, .split_jmp = 0U};
// 	struct sbk_slot bslt = {
// 		.ctx = (void *)&bsctx,
// 		.read = boot_slot_read,
// 		.size = boot_slot_size,
// 		.address = boot_slot_address,
// 	};
// 	bool rv = false;

// 	SBK_IMAGE_STATE_CLR_FLAGS(st->state_flags);
// 	if (!sbk_image_is_valid(&bslt, st)) {
// 		goto end;
// 	}

// 	if (!SBK_IMAGE_STATE_IS_RUNNABLE(st->state_flags)) {
// 		goto end;
// 	}

// 	rv = true;
// end:
// 	return rv;
// }

// #if CONFIG_SBK_IMAGE_AUTHENTICATE == 0
// bool sbk_image_is_authentic(const struct sbk_slot *slt)
// {
// 	return true;
// }
// #else  /* todo add signature check */
// bool sbk_image_is_authentic(const struct sbk_slot *slt)
// {
// 	return true;
// }
// #endif /* CONFIG_SBK_IMAGE_AUTHENTICATE */

// static bool sbk_image_can_upgrade(const struct sbk_slot *dst,
// 				  const struct sbk_slot *src)
// {
// 	struct sbk_image_state dst_st, src_st;
// 	bool rv = false;

// 	SBK_IMAGE_STATE_CLR_FLAGS(dst_st.state_flags);
// 	SBK_IMAGE_STATE_CLR_FLAGS(src_st.state_flags);
// 	(void)sbk_image_get_state(dst, &dst_st);

// 	if (!sbk_image_is_authentic(src)) {
// 		goto end;
// 	}

// 	if (!sbk_image_is_valid_header(src, &src_st)) {
// 		goto end;
// 	}

// 	if (src_st.im.image_sequence_number >= dst_st.im.image_sequence_number) {
// 		rv = true;
// 	}

// 	if ((!rv) && (!SBK_IMAGE_STATE_ICONF_IS_SET(dst_st.state_flags))) {
// 		rv = true;
// 	}

// 	if ((!rv) && (!SBK_IMAGE_STATE_SCONF_IS_SET(dst_st.state_flags))) {
// 		rv = true;
// 	}

// end:
// 	return rv;
// }

// static int sbk_image_cipher(const struct sbk_image_meta *meta, uint32_t
// offset, 			    void *data, size_t len)
// {
// 	const size_t cbsize = sbk_crypto_cipher_block_size();
// 	const size_t cssize = sbk_crypto_cipher_state_size();
// 	const size_t cksize = sbk_crypto_kxch_km_size();
// 	uint8_t dbuf[cbsize], cbuf[cbsize], est[cssize], otk[cksize];
// 	uint8_t *data8 = (uint8_t *)data;
// 	int rc;

// 	if (offset < meta->image_offset) {
// 		return -SBK_EC_EINVAL;
// 	}

// 	sbk_image_get_ciph_key(meta, otk);

// 	while (len != 0U) {
// 		uint32_t bcnt = (offset - meta->image_offset) / cbsize;
// 		uint32_t boff = bcnt * cbsize + meta->image_offset;

// 		memset(dbuf, 0, cbsize);
// 		memcpy(dbuf + (offset - boff), data8, cbsize - (offset - boff));
// 		sbk_crypto_cipher_init(est, otk, sizeof(otk), bcnt);
// 		sbk_crypto_cipher(cbuf, dbuf, cbsize, est);
// 		while ((len != 0U) && ((offset - boff) < cbsize)) {
// 			(*data8) = cbuf[offset - boff];
// 			data8++;
// 			offset++;
// 			len--;
// 		}
// 	}

// 	sbk_crypto_cwipe(dbuf, sizeof(dbuf));
// 	sbk_crypto_cwipe(cbuf, sizeof(cbuf));
// 	sbk_crypto_cwipe(est, sizeof(est));
// 	sbk_crypto_cwipe(otk, sizeof(otk));
// 	return rc;
// }

// int sbk_image_read(const struct sbk_slot *slot, uint32_t off, void *data,
// 		   size_t len)
// {
// 	uint8_t *data8 = (uint8_t *)data;
// 	struct sbk_image_meta im;
// 	int rc;

// 	rc = sbk_image_get_tagdata(slot, SBK_IMAGE_META_TAG, &im, sizeof(im));
// 	if (rc != 0) {
// 		goto end;
// 	}

// 	if (off < im.image_offset) {
// 		size_t rdlen = SBK_MIN(len, im.image_offset - off);
// 		rc = sbk_slot_read(slot, off, data8, rdlen);
// 		if ((rc != 0) || (rdlen == len)) {
// 			goto end;
// 		}

// 		off += rdlen;
// 		len -= rdlen;
// 		data8 += rdlen;
// 	}

// 	/* Limit read to image data */
// 	if ((off + len) > (im.image_offset + im.image_size)) {
// 		len = (im.image_offset + im.image_size - off);
// 	}

// 	uint32_t saddr = im.image_offset;
// 	if ((!SBK_IMAGE_ENCRYPTED(im.image_flags)) ||
// 	    (sbk_slot_address(slot, &saddr) != 0) ||
// 	    (saddr != im.image_start_address)) {
// 		rc = sbk_slot_read(slot, off, data8, len);
// 	} else {
// 		rc = sbk_image_cipher(&im, off, data8, len);
// 	}

// end:
// 	return rc;
// }

// static int stream_read(const void *ctx, uint32_t off, void *data, size_t len)
// {
// 	const struct sbk_stream_image_ctx *si_ctx =
// 		(const struct sbk_stream_image_ctx *)ctx;
// 	uint8_t *data8 = (uint8_t *)data;
// 	int rc = 0;

// 	while ((off < si_ctx->soff) && (len != 0U)) {
// 		size_t rdlen = SBK_MIN(si_ctx->soff - off, len);
// 		rc = sbk_slot_read(si_ctx->slt, off, data8, rdlen);
// 		if (rc != 0) {
// 			goto end;
// 		}

// 		len -= rdlen;
// 		off += rdlen;
// 		data8 += rdlen;
// 	}

// 	if (len != 0U) {
// 		memcpy(data8, si_ctx->sdata, len);
// 	}

// end:
// 	return rc;
// }

// int stream_address(const void *ctx, uint32_t *address)
// {
// 	const struct sbk_stream_image_ctx *si_ctx =
// 		(const struct sbk_stream_image_ctx *)ctx;

// 	return sbk_slot_address(si_ctx->slt, address);
// }

// int sbk_stream_image_flush(struct sbk_stream_image_ctx *ctx, size_t len)
// {
// 	uint8_t buf[SBK_IMAGE_WBS];
// 	struct sbk_slot stream_slot = {
// 		.ctx = (void *)ctx,
// 		.read = stream_read,
// 		.address = stream_address,
// 	};
// 	int rc;

// 	if ((ctx->soff == 0U) && (ctx->validate) &&
// 	    (!sbk_image_can_upgrade(ctx->slt, &stream_slot))) {
// 		return -SBK_EC_EFAULT;
// 	}

// 	while (len != 0) {
// 		size_t rdlen = SBK_MIN(len, sizeof(buf));

// 		rc = sbk_image_read(&stream_slot, ctx->soff, buf, rdlen);
// 		if (rc != 0) {
// 			goto end;
// 		}

// 		rc = sbk_slot_prog(ctx->slt, ctx->soff, buf, rdlen);
// 		if (rc != 0) {
// 			goto end;
// 		}

// 		ctx->soff += rdlen;
// 		len -= rdlen;
// 	}

// end:
// 	return rc;
// }

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
