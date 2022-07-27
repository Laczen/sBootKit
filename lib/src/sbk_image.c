/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sbk/sbk_image.h"
#include "sbk/sbk_crypto.h"

#define TLV_AREA_MIN_SIZE 256
#define TLV_AREA_MAX_SIZE 1024
#define TLV_AREA_SIGN_SIZE SIGNATURE_BYTES
#define TLVE_IMAGE_HASH 0x0100
#define TLVE_IMAGE_HASH_BYTES HASH_BYTES
#define TLVE_IMAGE_EPUBKEY 0x0200
#define TLVE_IMAGE_EPUBKEY_BYTES PUBLIC_KEY_BYTES
#define TLVE_IMAGE_DEPS 0x0300
#define TLVE_IMAGE_DEPS_BYTES sizeof(struct sbk_img_dep)
#define TLVE_IMAGE_CONF 0x0400
#define TLVE_IMAGE_CONF_BYTES 0

int img_get_info(struct sbk_blk *blk, struct sbk_img_info *info)
{
        int rc;
        void *ctx = sbk_cfg0.ctx;
        struct sbk_hdr hdr;

        SBK_LOG_DBG("img_get_info [%d][%d][%x]", blk->image, blk->area,
                    blk->offset);

        blk->offset = 0U;
        rc = sbk_cfg0.read(ctx, blk, &hdr, sizeof(struct sbk_hdr));
        if (rc) {
                return rc;
        }

        if ((hdr.magic != HDR_MAGIC) || (hdr.hdr_info.sigtype != 0) ||
            (hdr.hdr_info.siglen != SIGNATURE_BYTES)) {
                return -SBK_EC_EFAULT;
        }

        SBK_LOG_DBG("img_get_info: magic [%x] size [%d] hdrsize [%d]", 
                    hdr.magic, hdr.size, hdr.hdr_info.size);

        info->start = hdr.hdr_info.size;
        info->end = info->start + hdr.size;
        info->load_address = hdr.run_offset;
            info->version = SBK_VER(hdr.ver.major, hdr.ver.minor, hdr.ver.rev);
            info->build = hdr.build;
        return 0;

}

int img_verify_hdr(struct sbk_blk *blk, struct sbk_img_info *info)
{
        int rc;
        void *ctx = sbk_cfg0.ctx;
        uint32_t tsize;
        uint8_t buf[HASH_BYTES];
        uint8_t signature[SIGNATURE_BYTES];
        struct sbk_sha_ctx sha_ctx;

        rc = img_get_info(blk, info);

        SBK_LOG_DBG("img_verify_hdr [%d][%d][%x]", blk->image, blk->area,
                    blk->offset);
        
        /* Verify the image header signature */
        tsize = info->start - SIGNATURE_BYTES;
        rc = sbk_hash_init(&sha_ctx);
        if (rc) {
                return rc;
        }

        while (tsize) {
                uint32_t rd_size = SBK_MIN(sizeof(buf), tsize);
                rc = sbk_cfg0.read(ctx, &blk, buf, rd_size);
                if (rc) {
                        return rc;
                }

                rc = sbk_hash_update(&sha_ctx, buf, rd_size);
                if (rc) {
                        return rc;
                }

                blk->offset += rd_size;
                tsize -=rd_size;
        }

        rc = sbk_hash_final(&sha_ctx, buf);
        if (rc) {
                return rc;
        }

        rc = sbk_cfg0.read(ctx, &blk, signature, sizeof(signature));
        if (rc) {
                return rc;
        }

        rc = zb_sign_verify(buf, signature);
        SBK_LOG_DBG("img_verify_hdr [%s]", rc == 0 ? "OK" : "ERROR");
        return rc;
}

int img_get_enc_info(struct sbk_blk *blk, struct sbk_img_info *info,
                     struct sbk_img_enc_info *enc_info)
{

}

int img_get_img_hash(struct sbk_blk *blk, struct sbk_img_info *info, 
                     uin8_t *hash)
{

}

static int img_check_dep(struct sbk_img_dep *dep)
{
        bool dep_loc_found = false;
        void *ctx = sbk_cfg0.ctx; 
        struct sbk_hdr hdr;
        struct sbk_blk blk;
        int rc;

        blk.area = SBK_IA_RUN;
        for (uint32_t cnt = sbk_cfg0.get_image_count(ctx); cnt > 0U; --cnt) {
                blk.image = cnt;
                rc = sbk_cfg0.read(ctx, &blk, &hdr, sizeof(struct sbk_hdr));
                if (rc) {
                        return rc;
                }

                if (hdr.magic != HDR_MAGIC) {
                        continue;
                }

                if (dep->img_offset != hdr.run_offset) {
                        continue;
                }

                if (SBK_VER(hdr.ver.major, hdr.ver.minor, hdr.ver.rev) <
                    SBK_VER(dep->ver_min.major, dep->ver_min.minor, dep->ver_min.rev)) {
                        continue;
                }

                if (SBK_VER(hdr.ver.major, hdr.ver.minor, hdr.ver.rev) >
                    SBK_VER(dep->ver_max.major, dep->ver_max.minor, dep->ver_max.rev)) {
                        continue;
                }
                              
                return 0;
        }

        return -SBK_EC_EFAULT;
}

static int img_get_info(struct zb_img_info *info, struct zb_slt_info *slt_info,
                        struct zb_slt_info *dst_slt_info, bool full_check)
{
        int rc;
        u32_t off;
        struct tlv_entry entry;
        struct zb_fsl_hdr hdr;
        struct zb_img_dep *dep;
        size_t tsize;
        u8_t tlv[TLV_AREA_MAX_SIZE];
        u8_t hdrhash[HASH_BYTES];
        u8_t imghash[HASH_BYTES];
        u8_t sign[SIGNATURE_BYTES];

        rc = zb_read(slt_info, 0U, &hdr, sizeof(struct zb_fsl_hdr));
        if (rc) {
                return rc;
        }

        LOG_DBG("Magic [%x] Size [%u] HdrSize [%u]",
                hdr.magic, hdr.size, hdr.hdr_info.size);
        if ((hdr.magic != FSL_MAGIC) || (hdr.hdr_info.sigtype !=0) ||
            (hdr.hdr_info.siglen != sizeof(sign))) {
                return -EFAULT;
        }

        if (!full_check) {
                return 0;
        }

        tsize = hdr.hdr_info.size - sizeof(sign);
        /* Verify the image header signature */
        if (!info->hdr_ok) {
                rc = zb_hash(hdrhash, slt_info, 0U, tsize);
                if (rc) {
                        return rc;
                }
                rc = zb_read(slt_info, tsize, sign, sizeof(sign));
                if (rc) {
                        return rc;
                }
                rc = zb_sign_verify(hdrhash, sign);
                if (rc) {
                        LOG_DBG("HDR SIGNATURE INVALID");
                        return -EFAULT;
                }
                LOG_DBG("HDR SIGNATURE OK");
                info->hdr_ok = true;
        }

        info->start = hdr.hdr_info.size;
        info->enc_start = info->start;
        info->end = info->start + hdr.size;
        info->load_address = hdr.run_offset;
            info->version = (u32_t)(hdr.version.major << 24) +
                            (u32_t)(hdr.version.minor << 16) +
                        (u32_t)(hdr.version.rev);
            info->build = hdr.build;


        tsize -= sizeof(struct zb_fsl_hdr);
        rc = zb_read(slt_info, sizeof(struct zb_fsl_hdr), tlv, tsize);
        if (rc) {
                 return rc;
        }

        /* Get the confirmation status */
        off = 0;
        while ((!zb_step_tlv(tlv, &off, &entry)) &&
               (entry.type != TLVE_IMAGE_CONF) &&
               (entry.length != TLVE_IMAGE_CONF_BYTES));
        if ((entry.type == TLVE_IMAGE_CONF) &&
            (entry.length == TLVE_IMAGE_CONF_BYTES)) {
                LOG_DBG("IMG CONFIRMED");
                info->confirmed = true;
        }

        /* Verify the image hash */
        off = 0;
        while ((!zb_step_tlv(tlv, &off, &entry)) &&
               (entry.type != TLVE_IMAGE_HASH) &&
               (entry.length != TLVE_IMAGE_HASH_BYTES));

        if (entry.type != TLVE_IMAGE_HASH) {
                return -EFAULT;
        }

        if (!info->img_ok) {
                rc = zb_hash(imghash, slt_info, info->start, hdr.size);
                if (rc) {
                        LOG_DBG("HASH CALC Failure");
                        return -EFAULT;
                }
                if (memcmp(entry.value, imghash, HASH_BYTES)) {
                        LOG_DBG("IMG HASH INVALID");
                        return -EFAULT;
                }
                LOG_DBG("IMG HASH OK");
                info->img_ok = true;
        }

        /* Get the encryption parameters */
        off = 0;
        while ((!zb_step_tlv(tlv, &off, &entry)) &&
               (entry.type != TLVE_IMAGE_EPUBKEY) &&
               (entry.length != TLVE_IMAGE_EPUBKEY_BYTES));

        if (!entry.type) {
                /* No encryption key -> no encryption used */
                LOG_DBG("IMG NOT ENCRYPTED");
                info->enc_start = info->end;
        } else {
                if (!info->key_ok) {
                        if (zb_get_encr_key(info->enc_key, info->enc_nonce,
                                            entry.value, AES_KEY_SIZE)) {
                                return -EFAULT;
                        }
                        info->key_ok = true;
                }
                LOG_DBG("IMG ENCRYPTED KEY OK");
                info->enc_start = info->start;
        }

        if (info->dep_ok) {
                return 0;
        }

        /* Validate the depencies */
        off = 0;
        while (!zb_step_tlv(tlv, &off, &entry)) {
                if ((entry.type != TLVE_IMAGE_DEPS) ||
                           (entry.length != TLVE_IMAGE_DEPS_BYTES)) {
                        continue;
                }
                dep = (struct zb_img_dep *)entry.value;
                if (!info->confirmed &&
                   (dep->img_offset == dst_slt_info->offset)) {
                        dep->ver_min.major = dep->ver_max.major;
                        dep->ver_min.minor = dep->ver_max.minor;
                }
                if (img_check_dep(dep)) {
                        LOG_DBG("IMG DEPENDENCY FAILURE");
                        return -EFAULT;
                }
        }
        LOG_DBG("IMG DEPENDENCIES OK");
        info->dep_ok = true;
        LOG_INF("Finshed img validation");
        return 0;
}

void zb_res_img_info(struct zb_img_info *info)
{
        info->hdr_ok = false;
        info->img_ok = false;
        info->dep_ok = false;
        info->key_ok = false;
        info->confirmed = false;
}

int zb_val_img_info(struct zb_img_info *info, struct zb_slt_info *slt_info,
                    struct zb_slt_info *dst_slt_info)
{
        return img_get_info(info, slt_info, dst_slt_info, true);
}

int zb_get_img_info(struct zb_img_info *info, struct zb_slt_info *slt_info)
{
        return img_get_info(info, slt_info, slt_info, true);
}

int sbk_blk_has_img_hdr(struct sbk_blk *blk)
{
        struct zb_img_info info;
        return img_get_info(&info, slt_info, slt_info, false);
}

bool zb_img_info_valid(struct zb_img_info *info)
{
        return info->hdr_ok & info->img_ok & info->dep_ok;
}