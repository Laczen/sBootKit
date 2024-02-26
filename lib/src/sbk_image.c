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

static bool sbk_image_info_ok(const struct sbk_slot *slot,
			      struct sbk_image_info *info)
{
	const uint16_t tag = SBK_IMAGE_INFO_TAG;
	const size_t dsize = sizeof(struct sbk_image_info);

	return (sbk_tlv_get_data(slot, tag, info, dsize) == 0);
}

static bool sbk_image_address_match(const struct sbk_slot *slot,
				    uint32_t offset, uint32_t address)
{
	uint32_t tmp = offset;

	if ((sbk_slot_address(slot, &tmp) != 0) || (tmp != address)) {
		return false;
	}
	
	return true;
}

static bool sha256_verify(const struct sbk_slot *slot, uint32_t rdoff,
			  size_t rdsize, const void *sha256)
{
	const struct sbk_crypto_slot_ctx sctx = {
		.slot = slot,
		.soff = rdoff,
	};
	const struct sbk_crypto_read_ctx rdctx = {
		.read = sbk_crypto_slot_read,
		.ctx = (void *)&sctx,
	};
	const struct sbk_crypto_sha_ctx hctx = {
		.sha = sha256,
		.sha_size = SBK_SHA256_SIZE,
		.chunk_size = 512,
	};

	return (sbk_crypto_sha256_vrfy(&hctx, &rdctx, rdsize) == 0);
}

static bool header_ic_ok_cb(const struct sbk_tlv_info *info, void *cb_arg)
{
	const uint32_t rdpos = info->pos + sizeof(struct sbk_tlv_rhdr);
	const size_t rdsize = sizeof(struct sbk_image_fsl_int);
	struct sbk_image_fsl_int fsl_int;
	bool rv = false; 

	if (((info->pos + info->size) != (rdpos + rdsize)) ||
	    (sbk_slot_read(info->slot, rdpos, &fsl_int, rdsize) != 0)) {
		goto end;
	}
	
	rv = sha256_verify(info->slot, 0, info->pos,
			   (void *)&fsl_int.sha256[0]);
end:
	return rv;
}

static bool sbk_image_hic_ok(const struct sbk_slot *slot)
{
	bool rv = sbk_tlv_tag_cb(slot, SBK_IMAGE_FSLI_TAG0, header_ic_ok_cb,
				 NULL);

	SBK_LOG_DBG("header integrity %s", rv ? "ok" : "bad");
	return rv;
}

static bool sbk_image_iic_ok(const struct sbk_slot *slot)
{
	const uint16_t tag = SBK_IMAGE_INFO_TAG;
	const size_t dsize = sizeof(struct sbk_image_info); 
	struct sbk_image_info image_info;
	bool rv = false;

	if (sbk_tlv_get_data(slot, tag, &image_info, dsize) != 0) {
		goto end;
	}
	
	rv = sha256_verify(slot, image_info.image_offset, image_info.image_size,
			   (void *)&image_info.sha256[0]);

end:
	SBK_LOG_DBG("image integrity %s", rv ? "ok" : "bad");
	return rv;
}

#ifdef CONFIG_SBK_PRODUCT_DEP
static bool pdep_ok_cb(const struct sbk_tlv_info *info, void *cb_arg)
{
	const uint32_t rdpos = info->pos + sizeof(struct sbk_tlv_rhdr);
	const size_t rdsize = sizeof(struct sbk_product_dep_info);
	struct sbk_product_dep_info dep_info;
	struct sbk_product_data data;
	uint16_t *tag = (uint16_t *)cb_arg;
	bool rv = false;

	if (sbk_tlv_get_product_data(&data) != 0) {
		rv = true;
		goto end;
	}

	if (((info->pos + info->size) != (rdpos + rdsize)) ||
	    (sbk_slot_read(info->slot, rdpos, &dep_info, rdsize) != 0)) {
		goto end;
	}

	*tag = dep_info.next_tag;
	if (sbk_crypto_compare(dep_info.guid, data.guid,
			       SBK_PRODUCT_GUID_SIZE) != 0) {
		goto end;
	}

	if (sbk_version_in_range(&data.version, &dep_info.vrange)) {
		rv = true;
	}

end:
	return rv;
}

static bool sbk_image_pdep_ok(const struct sbk_slot *slot, uint16_t tag)
{
	bool rv = false;

	if (tag == SBK_IMAGE_LEND_TAG) {
		rv = true;
		goto end;
	}

	while ((!rv) && (tag != SBK_IMAGE_LEND_TAG)) {
		uint16_t next_tag;
		
		rv = sbk_tlv_tag_cb(slot, tag, pdep_ok_cb, (void *)&next_tag);
		tag = next_tag;
	}

end:
	SBK_LOG_DBG("product dependency %s", rv ? "ok" : "bad");
	return rv;
}
#else
static bool sbk_image_pdep_ok(const struct sbk_slot *slot, uint16_t tag)
{
	return true;
}
#endif

#ifdef CONFIG_SBK_IMAGE_DEP
static bool idep_ok_cb(const struct sbk_tlv_info *info, void *cb_arg)
{
	const uint32_t rdpos = info->pos + sizeof(struct sbk_tlv_rhdr);
	const size_t rdsize = sizeof(struct sbk_image_dep_info);
	struct sbk_image_dep_info dep_info;
	uint16_t *tag = (uint16_t *)cb_arg;
	bool rv = false;

	if (((info->pos + info->size) != (rdpos + rdsize)) ||
	    (sbk_slot_read(info->slot, rdpos, &dep_info, rdsize) != 0)) {
		goto end;
	}

	*tag = dep_info.next_tag;
	uint32_t slot_no = 0U;
	while (!rv) {
		struct sbk_slot slot;
		struct sbk_image_info image_info;

		if (sbk_open_image_slot(&slot, slot_no) != 0) {
			break;
		}

		if ((!sbk_image_hic_ok(&slot)) || 
		    (!sbk_image_info_ok(&slot, &image_info)) ||
		    (!sbk_image_address_match(&slot, image_info.image_offset,
		    		    	      dep_info.image_start_address)) ||
		    (sbk_version_in_range(&image_info.image_version,
		    			  &dep_info.vrange))) {
			rv = false;
		}

		if (rv) {
			rv = sbk_image_iic_ok(&slot);
		}

		sbk_slot_close(&slot);
	}
end:
	return rv;
}

static bool sbk_image_idep_ok(const struct sbk_slot *slot, uint16_t tag)
{

	bool rv = false;

	if (tag == SBK_IMAGE_LEND_TAG) {
		rv = true;
		goto end;
	}

	uint32_t dcnt = 0U, okcnt = 0U;
	while (tag != SBK_IMAGE_LEND_TAG) {
		uint16_t next_tag;

		dcnt++;
		if (sbk_tlv_tag_cb(slot, tag, idep_ok_cb, (void *)&next_tag)) {
			okcnt++;
		}

		tag = next_tag;
	}

	if (dcnt == okcnt) {
		rv = true;
	}

end:
	SBK_LOG_DBG("image dependency %s", rv ? "ok" : "bad");
	return rv;
}
#else
static bool sbk_image_idep_ok(const struct sbk_slot *slot, uint16_t tag)
{
	return true;
}
#endif

/* first stage loader (fsl) specific routines */
void sbk_image_fsl_state(const struct sbk_slot *slot,
			  struct sbk_image_state_info *state_info)
{
	struct sbk_image_info info;

	SBK_IMAGE_STATE_CLR(state_info->state, SBK_IMAGE_STATE_FULL);
	
	if (sbk_image_hic_ok(slot)) {
	 	SBK_IMAGE_STATE_SET(state_info->state, SBK_IMAGE_STATE_FSLI);
	}

	if (!sbk_image_info_ok(slot, &info)) {
		goto end;
	}
	
	SBK_IMAGE_STATE_SET(state_info->state, SBK_IMAGE_STATE_IINF);
	state_info->image_start_address = info.image_start_address;
	state_info->image_sequence_number = info.image_sequence_number;

	if (SBK_IMAGE_FLAG_ISSET(info.image_flags, SBK_IMAGE_FLAG_TEST)) {
	 	SBK_IMAGE_STATE_SET(state_info->state, SBK_IMAGE_STATE_TEST);
	}
	
	if (sbk_image_address_match(slot, info.image_offset,
				    info.image_start_address)) {
		SBK_IMAGE_STATE_SET(state_info->state, SBK_IMAGE_STATE_INDS);
	}

	if (sbk_image_idep_ok(slot, info.idep_tag)) {
		SBK_IMAGE_STATE_SET(state_info->state, SBK_IMAGE_STATE_IDEP);
	}

	if (sbk_image_pdep_ok(slot, info.pdep_tag)) {
		SBK_IMAGE_STATE_SET(state_info->state, SBK_IMAGE_STATE_PDEP);
	}

	if (sbk_image_iic_ok(slot)) {
		SBK_IMAGE_STATE_SET(state_info->state, SBK_IMAGE_STATE_IMGI);
	}
end:
}

/* second stage loader (ssl) specific routines */
static bool ssl_p256_int_ok_cb(const struct sbk_tlv_info *info, void *cb_arg)
{
	const uint32_t rdpos = info->pos + sizeof(struct sbk_tlv_rhdr);
	const struct sbk_key *public_key = sbk_get_public_key();
	size_t pk_off = 0U;
	struct sbk_image_ssl_p256_int integr;
	bool rv = false;

	if (((info->pos + info->size) != (rdpos + sizeof(integr))) ||
	    (sbk_slot_read(info->slot, rdpos, &integr, sizeof(integr)) != 0)) {
		goto end;
	}

	while (pk_off < public_key->key_size) {
		const struct sbk_crypto_sig_p256_ctx p256_ctx = {
			.pubkey = (void *)&public_key->key[pk_off],
			.pubkey_size = SBK_P256_PUBK_SIZE,
			.signature = &integr.sign[0],
			.signature_size = SBK_P256_SIGN_SIZE,
		};
		const struct sbk_crypto_slot_ctx sctx = {
			.slot = info->slot,
			.soff = 0U,
		};
		const struct sbk_crypto_read_ctx rdctx = {
			.read = sbk_crypto_slot_read,
			.ctx = (void *)&sctx,
		};

		if (sbk_crypto_sig_p256_vrfy(&p256_ctx, &rdctx, info->pos) == 0)
		{
			rv = true;
			break;
		}

		pk_off += SBK_P256_PUBK_SIZE;
	}

end:
	return rv;
}

static bool sbk_image_ssl_int_ok(const struct sbk_slot *slot)
{
	const uint16_t tag = SBK_IMAGE_SSLI_TAG0;
	bool rv = sbk_tlv_tag_cb(slot, tag, ssl_p256_int_ok_cb, NULL);

	SBK_LOG_DBG("ssl p256 integrity %s", rv ? "valid" : "invalid");
	return rv;
}

static bool cipher0_key_cb(const struct sbk_tlv_info *info, void *cb_arg)
{
	const uint32_t rdpos = info->pos + sizeof(struct sbk_tlv_rhdr);
	const struct sbk_key *private_key = sbk_get_private_key();
	struct sbk_key *otk = (struct sbk_key *)cb_arg;
	struct sbk_image_ssl_cipher0 cipher;
	uint8_t context[] = SBK_IMAGE_CIPH_CONTEXT;
	struct sbk_crypto_kxch_ctx kxctx = {
		.pkey = private_key->key,
		.pkey_size = private_key->key_size,
		.context = context,
		.context_size = sizeof(context) - 1,
	};
	bool rv = false;

	if ((private_key == NULL) ||
	    ((info->pos + info->size) != (rdpos + sizeof(cipher))) ||
	    (sbk_slot_read(info->slot, rdpos, &cipher, sizeof(cipher)) != 0)) {
		goto end;
	}

	kxctx.salt = &cipher.salt[0];
	kxctx.salt_size = SBK_CIPHER_SALT_SIZE;
	sbk_crypto_hkdf_sha256_kxch(&kxctx, otk->key, otk->key_size);
	sbk_crypto_cwipe(context, sizeof(context));
	sbk_crypto_cwipe(&kxctx, sizeof(kxctx));
	rv = true;
end:
	return rv;
}

static int sbk_image_ssl_retrieve_cipher_key(const struct sbk_slot *slot,
					     uint8_t *key, size_t key_size)
{
	struct sbk_key cb_arg = {
		.key = key,
		.key_size = key_size,
	};
	uint16_t tag;

	tag = SBK_IMAGE_SSLC_TAG0;
	if (sbk_tlv_tag_cb(slot, tag, cipher0_key_cb, (void *)&cb_arg)) {
		return 0;
	}

	/* other cipher key retrieve routines can be added here */
	return -SBK_EC_EINVAL;
}

static int sbk_image_ciphered_read(const struct sbk_crypto_slot_ctx *sctx,
				   uint32_t off, void *data, size_t len)
{
	const size_t otksz = sbk_crypto_ciphered_read_km_size(); 
	uint8_t otk[otksz];
	uint8_t *data8 = (uint8_t *)data;
	int rc;

	if (sbk_image_ssl_retrieve_cipher_key(sctx->slot, otk, otksz) != 0) {
		return sbk_slot_read(sctx->slot, off, data, len);
	}
	
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

	const struct sbk_crypto_read_ctx rdctx = {
		.ctx = sctx,
		.read = sbk_crypto_slot_read,
	};
	const struct sbk_crypto_ciphered_read_ctx crdctx = {
		.read_ctx = &rdctx,
		.key = otk,
		.key_size = otksz,
	};

	rc = sbk_crypto_ciphered_read(&crdctx, off - sctx->soff, data8, len);
end:
	return rc;
}

bool sbk_image_in_destination_slot(const struct sbk_slot *slot, uint32_t *off)
{
	struct sbk_image_info info;
	bool rv = false;

	if (!sbk_image_info_ok(slot, &info)) {
		goto end;
	}

	*off = info.image_offset;
	rv = sbk_image_address_match(slot, *off, info.image_start_address);
end:
	return rv;
}

int sbk_image_read(const struct sbk_slot *slot, uint32_t off, void *data,
		   size_t len)
{
	uint32_t img_offset;

	if (!sbk_image_in_destination_slot(slot, &img_offset)) {
		return sbk_slot_read(slot, off, data, len);
	}

	const struct sbk_crypto_slot_ctx sctx = {
		.slot = slot,
		.soff = img_offset,
	};

	return sbk_image_ciphered_read(&sctx, off, data, len);
}

static int sbk_image_read_decrypted(const struct sbk_slot *slot, uint32_t off,
				    void *data, size_t len)
{
	uint32_t img_offset;

	if (sbk_image_in_destination_slot(slot, &img_offset)) {
		return sbk_slot_read(slot, off, data, len);
	}

	const struct sbk_crypto_slot_ctx sctx = {
		.slot = slot,
		.soff = img_offset,
	};

	return sbk_image_ciphered_read(&sctx, off, data, len);
}

static int sbk_dslot_read(const void *ctx, uint32_t off, void *data, size_t len)
{
	const struct sbk_slot *slot = (const struct sbk_slot *)ctx;

	return sbk_image_read_decrypted(slot, off, data, len);
}

static int sbk_dslot_address(const void *ctx, uint32_t *address)
{
	const struct sbk_slot *slot = (const struct sbk_slot *)ctx;

	return sbk_slot_address(slot, address);
}

void sbk_image_ssl_state(const struct sbk_slot *slot,
			 struct sbk_image_state_info *state_info)
{
	struct sbk_image_info info;

	SBK_IMAGE_STATE_CLR(state_info->state, SBK_IMAGE_STATE_FULL);

	if (sbk_image_ssl_int_ok(slot)) {
	 	SBK_IMAGE_STATE_SET(state_info->state, SBK_IMAGE_STATE_SSLI);
	}
	
	if (sbk_image_hic_ok(slot)) {
	 	SBK_IMAGE_STATE_SET(state_info->state, SBK_IMAGE_STATE_FSLI);
	}

	if (!sbk_image_info_ok(slot, &info)) {
		goto end;
	}
	
	SBK_IMAGE_STATE_SET(state_info->state, SBK_IMAGE_STATE_IINF);
	state_info->image_start_address = info.image_start_address;
	state_info->image_sequence_number = info.image_sequence_number;

	if (SBK_IMAGE_FLAG_ISSET(info.image_flags, SBK_IMAGE_FLAG_TEST)) {
	 	SBK_IMAGE_STATE_SET(state_info->state, SBK_IMAGE_STATE_TEST);
	}

	if (sbk_image_address_match(slot, info.image_offset,
				    info.image_start_address)) {
		SBK_IMAGE_STATE_SET(state_info->state, SBK_IMAGE_STATE_INDS);
	}
	
	if (sbk_image_idep_ok(slot, info.idep_tag)) {
		SBK_IMAGE_STATE_SET(state_info->state, SBK_IMAGE_STATE_IDEP);
	}

	if (sbk_image_pdep_ok(slot, info.pdep_tag)) {
		SBK_IMAGE_STATE_SET(state_info->state, SBK_IMAGE_STATE_PDEP);
	}

	struct sbk_slot cslot = {
		.ctx = (void *)slot,
		.read = sbk_dslot_read,
		.size = slot->size,
		.address = sbk_dslot_address,
	};

	if (sbk_image_iic_ok(&cslot)) {
		SBK_IMAGE_STATE_SET(state_info->state, SBK_IMAGE_STATE_IMGI);
	}
end:
}

// struct sbk_split_slot_ctx {
// 	struct sbk_slot *start;
// 	struct sbk_slot *end;
// 	uint32_t soff;
// };

// static void sbk_image_sfsl_get_swap_state(struct sbk_image_swap_state *state)
// {
// 	struct sbk_image_info img_info, upd_info;
// 	bool img_ldok, upd_ldok, img_test;
	
// 	state->mode = SBK_IMAGE_SWAP_MODE_NONE;

// 	if ((state->img == NULL) || (state->upd == NULL)) {
// 		goto end;
// 	}

// 	SBK_IMAGE_STATE_CLR(upd_info.state, SBK_IMAGE_STATE_FULL);
// 	sbk_image_sldr_state(state->upd, &upd_info);
// 	upd_ldok = SBK_IMAGE_STATE_ISSET(upd_info.state, SBK_IMAGE_STATE_LDOK);
// 	SBK_IMAGE_STATE_CLR(img_info.state, SBK_IMAGE_STATE_FULL);
// 	sbk_image_sldr_state(state->img, &img_info);
// 	img_ldok = SBK_IMAGE_STATE_ISSET(img_info.state, SBK_IMAGE_STATE_LDOK);
// 	img_test = SBK_IMAGE_STATE_ISSET(img_info.state, SBK_IMAGE_STATE_TEST);

// 	while (upd_ldok) {
// 		const uint32_t off = upd_info.image_offset;
// 		const uint32_t addr = upd_info.image_start_address;

// 		if (!sbk_image_address_match(state->img, off, addr)) {
// 			goto end;
// 		}

// 		if (!img_ldok) {
// 			/* when the image is not valid, the image slot can be
// 			 * empty or the first block can be erased when the first
// 			 * update block needs to be copied to the image slot.
// 			 */
// 			state->mode = SBK_IMAGE_SWAP_MODE_UPDATE;
// 			break;
// 		}

// 		const uint32_t isn = img_info.image_sequence_number;
// 		const uint32_t usn = upd_info.image_sequence_number;

// 		if (usn < isn) {
// 			goto end; 
// 		}

// 		if (state->bck == NULL) {
// 			goto end;
// 		}

// 		state->mode = SBK_IMAGE_SWAP_MODE_SWAP;
// 		goto end;
// 	}

// 	if (state->bck == NULL) {
// 		goto end;
// 	}

// 	struct sbk_image_info bck_info;
// 	bool bck_ldok;

// 	SBK_IMAGE_STATE_CLR(bck_info.state, SBK_IMAGE_STATE_FULL);
// 	sbk_image_sldr_state(state->bck, &bck_info);
// 	bck_ldok = SBK_IMAGE_STATE_ISSET(bck_info.state, SBK_IMAGE_STATE_LDOK);

// 	if (bck_ldok) {
// 		const uint32_t off = bck_info.image_offset;
// 		const uint32_t addr = bck_info.image_start_address;

// 		if (!sbk_image_address_match(state->img, off, addr)) {
// 			goto end;
// 		}

// 		if (img_test) {
// 			state->mode = SBK_IMAGE_SWAP_MODE_RESTORE;
// 			goto end;
// 		}

// 		goto end;
// 	}

// 	if (SBK_IMAGE_STATE_ISSET(bck_info.state, SBK_IMAGE_STATE_IINF)) {
// 		const uint32_t off = bck_info.image_offset;
// 		const uint32_t addr = bck_info.image_start_address;

// 		if (!sbk_image_address_match(state->img, off, addr)) {
// 			goto end;
// 		}
// 	}

// 	size_t bsize;

// 	if (sbk_slot_size(state->bck, &bsize) != 0) {
// 		goto end;
// 	} 

// 	(void)sbk_slot_cmd(state->bck, SBK_SLOT_CMD_GET_BACKUP_BLOCK_SIZE,
// 			   &bsize, sizeof(size_t));

// 	state->block_size = bsize;
// 	state->mode = SBK_IMAGE_SWAP_MODE_SWAP;

// 	if (upd_ldok) {

// 	}
// end:
// 	SBK_LOG_DBG("swap mode %d", state->mode);
// }

// static bool sbk_image_sfsl_do_swap(struct sbk_image_swap_state *state)
// {
// 	return false;
// }

// bool sbk_image_sfsl_swap(uint32_t idx)
// {
// 	struct sbk_image_swap_state swp_state = {
// 		.offset = 0U,
// 		.bck_done = 0U,
// 	};
// 	bool rv = false;

// 	if (sbk_open_image_slot(swp_state.img, idx) != 0) {
// 		swp_state.img = NULL;
// 		goto end;
// 	}

// 	if (sbk_open_update_slot(swp_state.upd, idx) != 0) {
// 		swp_state.upd = NULL;
// 		goto end;
// 	}

// 	if (sbk_open_backup_slot(swp_state.bck, idx) != 0) {
// 		swp_state.bck = NULL;
// 	}
	
// 	sbk_image_sfsl_get_swap_state(&swp_state);
// 	rv = sbk_image_sfsl_do_swap(&swp_state);
// end:
// 	if (swp_state.bck != NULL) {
// 		(void)sbk_slot_close(swp_state.bck);
// 	}

// 	if (swp_state.upd != NULL) {
// 		(void)sbk_slot_close(swp_state.upd);
// 	}

// 	if (swp_state.img != NULL) {
// 		(void)sbk_slot_close(swp_state.img);
// 	}

// 	return rv;
// }

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
