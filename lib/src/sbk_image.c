/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sbk/sbk_product.h"
#include "sbk/sbk_image.h"

#include <string.h>

#include "sbk/sbk_util.h"
#include "sbk/sbk_os.h"
#include "sbk/sbk_crypto.h"

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

static int sbk_image_get_tag_pos(const struct sbk_image *image, uint32_t *pos,
                                 uint16_t tag, uint16_t len)
{
        SBK_ASSERT(image);
        SBK_ASSERT(image->slot);

        struct sbk_image_rec_hdr rhdr;
        const struct sbk_os_slot *slot = image->slot;

        while (true) {
                if (sbk_os_slot_read(slot, *pos, &rhdr, sizeof(rhdr)) != 0) {
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

static int sbk_image_read_tag_data(const struct sbk_image *image, uint32_t pos,
                                   void *data, size_t len)
{
        SBK_ASSERT(image);
        SBK_ASSERT(image->slot);

        return sbk_os_slot_read(image->slot, pos, data, len);
}

static int sbk_image_get_tagdata(const struct sbk_image *image, uint16_t tag,
                                 void *data, size_t dlen)
{
        SBK_ASSERT(image);
        
        int rc;
        uint32_t spos = 0U;

        rc = sbk_image_get_tag_pos(image, &spos, tag, dlen);
        if (rc != 0) {
                goto end;
        }

        return sbk_image_read_tag_data(image, spos, data, dlen);
end:
        return rc;
}

static void sbk_image_authentic_key(void *km, const uint8_t *salt, 
                                   size_t salt_len)
{
        uint8_t prk[sbk_crypto_kxch_prk_size()];

        sbk_crypto_kxch_init(prk, salt, salt_len);
        sbk_crypto_kxch_final(km, prk, SBK_IMAGE_AUTH_CONTEXT, 
                              sizeof(SBK_IMAGE_AUTH_CONTEXT) - 1);

}

static void sbk_image_encryption_key(void *km, const uint8_t *salt, 
                                   size_t salt_len)
{
        uint8_t prk[sbk_crypto_kxch_prk_size()];

        sbk_crypto_kxch_init(prk, salt, salt_len);
        sbk_crypto_kxch_final(km, prk, SBK_IMAGE_ENCR_CONTEXT, 
                              sizeof(SBK_IMAGE_ENCR_CONTEXT) - 1);

}

static int sbk_image_authentic(const struct sbk_image *image,
                               const uint8_t *tag, size_t tlen, bool full)
{
        SBK_ASSERT(image);
        SBK_ASSERT(image->slot);

        int rc;
        struct sbk_image_meta meta;
        uint32_t pos, len;
        uint8_t otk[sbk_crypto_kxch_km_size()];
        uint8_t sbuf[sbk_crypto_auth_state_size()]; 
        uint8_t buf[64];

        rc = sbk_image_get_tagdata(image, SBK_IMAGE_META_TAG, (void *)&meta,
                                   sizeof(meta));
        if (rc) {
                goto end;
        }

        pos = sizeof(struct sbk_image_auth);
        len = meta.image_offset - pos;

        if (full) {
                len += meta.image_size;
        }

        sbk_image_authentic_key(otk, meta.salt, sizeof(meta.salt));
        sbk_crypto_auth_init(sbuf, otk, sizeof(otk));
        sbk_crypto_cwipe(otk, sizeof(otk));

        while (len != 0) {
                uint32_t rdlen = MIN(len, sizeof(buf));

                rc = sbk_os_slot_read(image->slot, pos, buf, rdlen);
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

static int sbk_image_product_dependency_verify(const struct sbk_image *image)
{
        SBK_ASSERT(image);

        int rc;
        struct sbk_image_meta meta;
        uint16_t tag = SBK_IMAGE_META_TAG;
        uint32_t dcnt, mcnt;

        rc = sbk_image_get_tagdata(image, tag, (void *)&meta, sizeof(meta));
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

                rc = sbk_image_get_tagdata(image, tag, (void *)&di, sizeof(di));
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
                rc = - SBK_EC_EFAULT;
        }

end:
        SBK_LOG_DBG("Product dependency [%d]", rc);
        return rc;
}

static int sbk_image_image_dependency_verify(const struct sbk_image *image)
{
        SBK_ASSERT(image);

        int rc;
        struct sbk_image_meta meta;
        uint16_t tag;
        uint32_t dcnt, mcnt;

        rc = sbk_image_get_tagdata(image, SBK_IMAGE_META_TAG, (void *)&meta,
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

                rc = sbk_image_get_tagdata(image, tag, (void *)&di, sizeof(di));
                if (rc != 0) {
                        goto end;
                }

                dcnt++;
                tag = di.next_tag;

                struct sbk_os_slot dslot;
                uint32_t dslt_idx = 0;
                uint32_t dep_img_address = di.image_start_address;

                while (true) {
                        rc = sbk_os_slot_open(&dslot, dslt_idx);
                        if (rc != 0) {
                                rc = - SBK_EC_EFAULT;
                                goto end;
                        }

                        if (sbk_os_slot_inrange(&dslot, dep_img_address)) {
                                break;
                        }

                        (void)sbk_os_slot_close(&dslot);
                        dslt_idx++;
                }

                struct sbk_image dimage = {
                        .slot = &dslot,
                };

                rc = sbk_image_get_tagdata(&dimage, SBK_IMAGE_META_TAG,
                                           (void *)&meta, sizeof(meta));

                (void)sbk_os_slot_close(&dslot);

                if (!sbk_version_in_range(&meta.image_version, &di.vrange)) {
                        continue;
                }

                mcnt++;
        }

        if (mcnt != dcnt) {
                rc = - SBK_EC_EFAULT;
        }

end:
        SBK_LOG_DBG("Image dependency [%d]", rc);
        return rc;
}

int sbk_image_dependency_verify(const struct sbk_image *image)
{
        SBK_ASSERT(image);

        int rc;

        rc = sbk_image_product_dependency_verify(image);
        if (rc) {
                goto end;
        }

        rc = sbk_image_image_dependency_verify(image);
end:
        return rc;
}

int sbk_image_bootable(const struct sbk_image *image, unsigned long *address,
                       uint8_t *bcnt)
{
        SBK_ASSERT(image);
        SBK_ASSERT(image->slot);

        int rc;
        struct sbk_image_meta meta;

        rc = sbk_image_get_tagdata(image, SBK_IMAGE_META_TAG, (void *)&meta,
                                   sizeof(meta));
        if (rc) {
                goto end;
        }

        if (!sbk_os_slot_inrange(image->slot, meta.image_start_address)) {
                rc = -SBK_EC_EFAULT;
                goto end;
        }

        rc = sbk_image_dependency_verify(image);
        if (rc != 0) {
                goto end;
        }

        struct sbk_image_auth auth;

        rc = sbk_image_get_tagdata(image, SBK_IMAGE_AUTH_TAG, (void *)&auth,
                                   sizeof(auth));
        if (rc != 0) {
                goto end;
        }

        rc = sbk_image_authentic(image, &auth.fsl_fhmac[0], 32, true);
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

int sbk_image_get_version(const struct sbk_image *image,
                          struct sbk_version *version)
{
        SBK_ASSERT(image);

        struct sbk_image_meta meta;
        int rc;

        rc = sbk_image_get_tagdata(image, SBK_IMAGE_META_TAG, (void *)&meta,
                                   sizeof(meta));
        if (rc != 0) {
                goto end;
        }

        memcpy(version, &meta.image_version, sizeof(struct sbk_version));
end:
        return rc;
}

/* read unencrypted part of image (offset is from slot start)*/
static int sbk_image_uread(const struct sbk_image *image, unsigned long offset,
                           void *data, size_t len)
{
        return sbk_os_slot_read(image->slot, offset, data, len);
}

/* read encrypted part of image (offset is from slot start)*/
static int sbk_image_eread(const struct sbk_image *image, unsigned long offset,
                           void *data, size_t len)
{
        int rc;
        struct sbk_image_meta meta;
        uint8_t eb[sbk_crypto_cipher_block_size()];
        uint8_t est[sbk_crypto_cipher_state_size()];
        uint8_t otk[sbk_crypto_kxch_km_size()];
        uint8_t *data8 = (uint8_t *)data;
        
        rc = sbk_image_get_tagdata(image, SBK_IMAGE_META_TAG, (void *)&meta,
                                   sizeof(meta));
        if (rc != 0) {
                goto end;
        }

        sbk_image_encryption_key(otk, meta.salt, sizeof(meta.salt));

        while (len != 0U) {
                const size_t bsz = sizeof(eb);
                const uint32_t bcnt = (offset - meta.image_offset) / bsz;
                const long unsigned boff = bcnt * bsz + meta.image_offset;
                const size_t rdlen = SBK_MIN(bsz, len + offset - boff);

                sbk_crypto_cipher_init(est, otk, sizeof(otk), bcnt);
                rc = sbk_os_slot_read(image->slot, boff, eb, bsz);
                if (rc) {
                        goto end;
                }

                sbk_crypto_cipher(est, eb, bsz);
                for (int i = offset - boff; i < bsz; ++i) {
                        (*data8++) = eb[i];
                }
                
                offset += rdlen;
                len -= rdlen;
        }

end:
        return rc;
}

int sbk_image_read(const struct sbk_image *image, unsigned long offset,
                   void *data, size_t len)
{
        SBK_ASSERT(image);
        SBK_ASSERT(image->slot);

        int rc;
        struct sbk_image_meta meta;
        size_t ulen = 0U;

        rc = sbk_image_get_tagdata(image, SBK_IMAGE_META_TAG, (void *)&meta,
                                   sizeof(meta));
        if (rc != 0) {
                goto end;
        }

        if (offset < meta.image_offset) {
                ulen = meta.image_offset - offset;
        }

        if ((!sbk_image_is_encrypted(meta.image_flags)) ||
            (!sbk_os_slot_inrange(image->slot, meta.image_start_address))) {
                ulen = len;
        }
        
        if (ulen != 0U) {
                rc = sbk_image_uread(image, offset, data, ulen);
                if (rc != 0) {
                        goto end;
                }

                len -= ulen;
        }

        if (len != 0U) {
                uint8_t *data8 = (uint8_t *)data;

                data8 += ulen;
                offset += ulen;
                rc = sbk_image_eread(image, offset, data8, len);
        }

end:
        return rc;
}

int sbk_image_write(const struct sbk_image *image, unsigned long offset,
                    const void *data, size_t len)
{
        SBK_ASSERT(image);
        SBK_ASSERT(image->slot);

        return 0;
}
