/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sbk/sbk_board.h"
#include "sbk/sbk_image.h"

#include <string.h>

#include "sbk/sbk_util.h"
#include "sbk/sbk_os.h"
#include "sbk/sbk_crypto.h"

struct __attribute__((packed)) sbk_image_hash {
        struct sbk_image_meta_rec_hdr rec_hdr;
        uint16_t type;
        uint16_t pad16;
        uint8_t digest[SBK_CRYPTO_FW_HASH_SIZE];
};

struct __attribute__((packed)) sbk_image_encryption_tranform_info {
        struct sbk_image_meta_rec_hdr rec_hdr;
        uint16_t type;
        uint16_t pad16;
        uint8_t ekdf[SBK_CRYPTO_FW_ENC_PUBKEY_SIZE];
};

struct __attribute__((packed)) sbk_image_seal {
        struct sbk_image_meta_rec_hdr rec_hdr;
        uint16_t type;
        uint16_t pad16;
        uint8_t seal[SBK_CRYPTO_FW_SEAL_SIZE];
};

static bool sbk_image_tag_is_odd_parity(uint16_t data)
{
        data ^= data >> 8;
        data ^= data >> 4;
        data &= 0xf;
        return ((0x6996 >> data) & 1U) == 1U;
}

int sbk_image_walk_tag(const struct sbk_os_slot *slot, uint16_t tag,
                       int (*cb)(void *cb_ctx, uint32_t pos, uint16_t rlen),
                       void *cb_ctx)
{
        uint32_t pos = 0U;
        struct sbk_image_meta_rec_hdr rhdr;

        while (true) {
                if (sbk_os_slot_read(slot, pos, &rhdr, sizeof(rhdr)) != 0) {
                        goto end;
                }

                if (!sbk_image_tag_is_odd_parity(rhdr.tag)) {
                        goto end;
                }

                if (rhdr.tag == tag) {
                        break;
                }

                pos += rhdr.len;
        }

        return cb(cb_ctx, pos, rhdr.len);
end:
        return -SBK_EC_ENOENT;
}

struct tagdata_cb_ctx {
        const struct sbk_os_slot *slot;
        void *data;
        uint32_t dsize;
};

static int tagdata_cb(void *cb_ctx, uint32_t pos, uint16_t rlen)
{
        struct tagdata_cb_ctx *ctx = (struct tagdata_cb_ctx *)cb_ctx;

        if (ctx->dsize != (uint32_t)rlen) {
                return -SBK_EC_ENOENT;
        }

        return sbk_os_slot_read(ctx->slot, pos, ctx->data, ctx->dsize);
}

int sbk_image_get_tag_data(const struct sbk_os_slot *slot, uint16_t tag,
                           void *data, uint32_t size)
{
        const struct tagdata_cb_ctx ctx = {
                .slot = slot,
                .data = data,
                .dsize = size,
        };

        return sbk_image_walk_tag(slot, tag, tagdata_cb, (void *)&ctx);
}

struct tagpos_cb_ctx {
        uint32_t *pos;
};

static int tagpos_cb(void *cb_ctx, uint32_t pos, uint16_t rlen)
{
        struct tagpos_cb_ctx *ctx = (struct tagpos_cb_ctx *)cb_ctx;

        *ctx->pos = pos;
        return 0;
}

int sbk_image_get_tag_pos(const struct sbk_os_slot *slot, uint16_t tag,
                          uint32_t *pos)
{
        const struct tagpos_cb_ctx ctx = {
                .pos = pos,
        };

        return sbk_image_walk_tag(slot, tag, tagpos_cb, (void *)&ctx);
}

int sbk_image_get_state(const struct sbk_os_slot *slot, uint32_t cnt,
                        struct sbk_image_state *state)
{
        struct sbk_image_meta_start start;
        int rc;

        rc = sbk_image_get_tag_data(slot, SBK_IMAGE_START_TAG, (void *)&start,
                                    sizeof(start));
        if (rc) {
                goto end;
        }

        uint16_t state_tag = start.image_state_tag;

        while (true) {
                rc = sbk_image_get_tag_data(slot, state_tag, (void *)state,
                                            sizeof(state));
                if (rc != 0) {
                        goto end;
                }

                if (cnt == 0U) {
                        break;
                }

                state_tag = state->next_tag;
                cnt--;
        }

end:
        return rc;
}

int sbk_image_hash_verify(const struct sbk_os_slot *slot,
                          int (*read_cb)(const void *ctx, uint32_t offset,
                                         void *data, uint32_t len),
                          const void *read_cb_ctx, uint32_t cnt)
{
        struct sbk_image_state state;
        int rc;

        rc = sbk_image_get_state(slot, cnt, &state);
        if (rc != 0) {
                goto end;
        }

        struct sbk_image_hash hash;

        rc = sbk_image_get_tag_data(slot, state.hash_tag, &hash, sizeof(hash));
        if (rc != 0) {
                goto end;
        }

        struct sbk_crypto_se hash_se = {
                .data = &hash,
        };

        /* verify the hash */
        return sbk_crypto_hash_verify(&hash_se, read_cb, read_cb_ctx,
                                      state.size);
end:
        return rc;
}

struct read_cb_ctx {
        const struct sbk_os_slot *slot;
        uint32_t offset;
};

static int read_cb(const void *ctx, uint32_t offset, void *data, uint32_t len)
{
        const struct read_cb_ctx *read = (const struct read_cb_ctx *)ctx;

        return sbk_os_slot_read(read->slot, read->offset + offset, data, len);
}

int sbk_image_seal_verify(const struct sbk_os_slot *slot)
{
        const uint16_t tag = SBK_IMAGE_SEAL_TAG;
        struct sbk_image_seal seal;
        int rc;

        rc = sbk_image_get_tag_data(slot, tag, &seal, sizeof(seal));
        if (rc != 0) {
                 goto end;
        }

        /* verify the image metadata hash */
        const struct read_cb_ctx cb_ctx = {
                .slot = slot,
        };
        struct sbk_crypto_se seal_se = {
                .data = &seal,
        };
        struct sbk_crypto_se hash_se = {
                .data = sbk_crypto_hash_from_seal(&seal_se),
        };
        uint32_t pos = 0U;

        rc = sbk_image_get_tag_pos(slot, tag, &pos);
        if (rc != 0) {
                goto end;
        }

        rc = sbk_crypto_hash_verify(&hash_se, read_cb, (void *)&cb_ctx, pos);
        if (rc != 0) {
                goto end;
        }

        /* verify the signature */
        rc = sbk_crypto_seal_verify(&seal_se);
end:
        return rc;
}

int sbk_image_pkey_compare(const struct sbk_os_slot *slot, uint8_t *pkey)
{
        const uint16_t tag = SBK_IMAGE_SEAL_TAG;
        struct sbk_image_seal seal;
        int rc;

        rc = sbk_image_get_tag_data(slot, tag, &seal, sizeof(seal));
        if (rc != 0) {
                 goto end;
        }

        struct sbk_crypto_se seal_se = {
                .data = &seal,
        };

        return sbk_crypto_seal_pkey_verify(&seal_se, pkey);
end:
        return rc;
}

int sbk_image_board_verify(const struct sbk_os_slot *slot)
{
        const uint16_t tag = SBK_IMAGE_START_TAG;
        struct sbk_image_meta_start start;
        uint16_t dep_tag, dep_cnt, dep_match_cnt;
        int rc;

        rc = sbk_image_get_tag_data(slot, tag, (void *)&start, sizeof(start));
        if (rc) {
                goto end;
        }

        dep_cnt = 0U;
        dep_match_cnt = 0U;
        dep_tag = start.board_dep_tag;

        while (true) {
                struct sbk_board_dep_info info;

                if (!sbk_image_tag_is_odd_parity(dep_tag)) {
                        break;
                }

                rc = sbk_image_get_tag_data(slot, dep_tag, (void *)&info,
                                            sizeof(info));
                if (rc != 0) {
                        goto end;
                }

                dep_cnt++;
                dep_tag = info.next_tag;
                uint32_t board_id = info.board_id;

                if (!sbk_board_id_match(&board_id)) {
                        continue;
                }

                struct sbk_version_range range = info.vrange;
                if (!sbk_board_version_in_range(&range)) {
                        continue;
                }

                dep_match_cnt++;
        }

        if ((dep_match_cnt == 0U) && (dep_cnt > 0)) {
                rc = - SBK_EC_EFAULT;
        }

end:
        return rc;
}

int sbk_image_dependency_verify(const struct sbk_os_slot *slot)
{
        const uint16_t tag = SBK_IMAGE_START_TAG;
        struct sbk_image_meta_start start;
        uint16_t dep_tag, dep_cnt, dep_match_cnt;
        int rc;

        rc = sbk_image_get_tag_data(slot, tag, (void *)&start, sizeof(start));
        if (rc) {
                goto end;
        }

        dep_cnt = 0U;
        dep_match_cnt = 0U;
        dep_tag = start.image_dep_tag;

        while (true) {
                struct sbk_image_dep_info info;

                if (!sbk_image_tag_is_odd_parity(dep_tag)) {
                        break;
                }

                rc = sbk_image_get_tag_data(slot, dep_tag, (void *)&info,
                                            sizeof(info));
                if (rc != 0) {
                        goto end;
                }

                dep_cnt++;
                dep_tag = info.next_tag;

                struct sbk_os_slot dep_slot;

                rc = sbk_os_slot_open(&dep_slot, info.run_slot);
                if (rc != 0) {
                        goto end;
                }

                rc = sbk_image_get_tag_data(&dep_slot, tag, (void *)&start,
                                            sizeof(start));
                if (rc != 0) {
                        goto end;
                }

                (void)sbk_os_slot_close(&dep_slot);

                if (!sbk_version_in_range(&start.image_version,
                                          &info.vrange)) {
                        continue;
                }

                dep_match_cnt++;
        }

        if (dep_match_cnt != dep_cnt) {
                rc = - SBK_EC_EFAULT;
        }

end:
        return rc;
}

int sbk_image_bootable(uint16_t slot_no, uint32_t *address)
{
        struct sbk_os_slot slot;
        struct sbk_image_state state;
        int rc;

        rc = sbk_os_slot_open(&slot, slot_no);
        if (rc != 0) {
                goto end;
        }

        rc = sbk_image_seal_verify(&slot);
        if (rc != 0) {
                goto end;
        }

        rc = sbk_image_get_state(&slot, 0, &state);
        if (rc != 0) {
                goto end;
        }

        if (state.slot != slot_no) {
                rc = -SBK_EC_EFAULT;
                goto end;
        }

        rc = sbk_image_board_verify(&slot);
        if (rc != 0) {
                goto end;
        }

        rc = sbk_image_dependency_verify(&slot);
        if (rc != 0) {
                goto end;
        }

        const struct read_cb_ctx cb_ctx = {
                .slot = &slot,
                .offset = state.offset,
        };

        rc = sbk_image_hash_verify(&slot, read_cb, (void *)&cb_ctx, 0U);
        if (rc != 0) {
                goto end;
        }

        *address = slot.get_start_address(slot.ctx) + state.offset;

        (void)sbk_os_slot_close(&slot);

end:
        return rc;
}