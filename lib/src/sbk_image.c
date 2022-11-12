/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sbk/sbk_sfsl.h"
#include "sbk/sbk_image.h"

#include <string.h>

#include "sbk/sbk_util.h"
#include "sbk/sbk_os.h"
#include "sbk/sbk_crypto.h"

struct __attribute__((packed)) sbk_image_seal {
        struct sbk_version header_signature_version;
        uint8_t seal[SBK_CRYPTO_FW_SEAL_SIZE];
};

struct __attribute__((packed)) sbk_image_info {
        struct sbk_version image_version;
        uint32_t image_jump_address;
        uint32_t image_size;
        uint8_t image_hash[SBK_CRYPTO_FW_HASH_SIZE];
        uint8_t encrypted_image_hash[SBK_CRYPTO_FW_HASH_SIZE];
        uint8_t kdf_key[SBK_CRYPTO_FW_ENC_PUBKEY_SIZE];
        uint8_t image_dep_cnt;
        uint8_t device_dep_cnt;
        uint16_t image_offset_in_slot;
};

struct hash_read_ctx {
        const struct sbk_os_slot *slot;
        uint32_t offset;
};

static int hash_read_cb(const void *ctx, uint32_t offset, void *data,
                        uint32_t len)
{
        const struct hash_read_ctx *read = (const struct hash_read_ctx *)ctx;
        return sbk_os_slot_read(read->slot, read->offset + offset, data, len);
}

int sbk_image_device_verify(const struct sbk_os_slot *slot,
                            const uint8_t *dev_uuid,
                            const struct sbk_version *dev_version)
{
        struct sbk_image_info info;
        uint32_t off;
        int rc;

        off = sizeof(struct sbk_image_seal);
        rc = sbk_os_slot_read(slot, off, &info, sizeof(info));
        if (rc != 0) {
                goto end;
        }

        if (info.device_dep_cnt == 0) {
                goto end;
        }

        off += sizeof(info);
        off += info.image_dep_cnt * sizeof(struct sbk_image_dep_info);
        for (int i = 0; i < info.device_dep_cnt; i++)
        {
                struct sbk_device_dep_info dep_info;
                uint8_t *dep_uuid = &dep_info.dev_uuid[0];
                struct sbk_version *min_version = &dep_info.vrange.min_version;
                struct sbk_version *max_version = &dep_info.vrange.max_version;

                rc = sbk_os_slot_read(slot, off, &dep_info, sizeof(dep_info));
                if (rc != 0) {
                        goto end;
                }

                off += sizeof(dep_info);

                if (memcmp(dev_uuid, dep_uuid, SBK_DEVICE_UUID_SIZE) != 0) {
                        continue;
                }

                if (sbk_version_u32(dev_version) <
                    sbk_version_u32(min_version)) {
                        continue;
                }

                if (sbk_version_u32(dev_version) >
                    sbk_version_u32(max_version)) {
                        continue;
                }

                goto end;
        }

        rc = -SBK_EC_ENOENT;
end:
        return rc;
}

int sbk_image_dependency_verify(const struct sbk_os_slot *slot)
{
        struct sbk_image_info info;
        uint32_t off;
        int rc;

        off = sizeof(struct sbk_image_seal);
        rc = sbk_os_slot_read(slot, off, &info, sizeof(info));
        if (rc != 0) {
                goto end;
        }

        if (info.image_dep_cnt == 0) {
                goto end;
        }

        off += sizeof(info);

        for (int i = 0; i < info.image_dep_cnt; i++)
        {
                struct sbk_os_slot dep_slot;
                struct sbk_image_info dep_image_info;
                struct sbk_image_dep_info dep_info;
                struct sbk_version *min_version = &dep_info.vrange.min_version;
                struct sbk_version *max_version = &dep_info.vrange.max_version;

                rc = sbk_os_slot_read(slot, off, &dep_info, sizeof(dep_info));
                if (rc != 0) {
                        goto end;
                }

                off += sizeof(dep_info);

                rc = sbk_os_slot_open(&dep_slot, dep_info.slot);
                if (rc != 0) {
                        goto end;
                }

                rc = sbk_os_slot_read(&dep_slot, sizeof(struct sbk_image_seal),
                                      &dep_image_info, sizeof(dep_image_info));
                if (rc != 0) {
                        goto end;
                }

                (void)sbk_os_slot_close(&dep_slot);

                if (sbk_version_u32(&dep_image_info.image_version) <
                    sbk_version_u32(min_version)) {
                        rc = -SBK_EC_EFAULT;
                        goto end;
                }

                if (sbk_version_u32(&dep_image_info.image_version) >
                    sbk_version_u32(max_version)) {
                        rc = -SBK_EC_EFAULT;
                        goto end;
                }

        }

end:
        return rc;
}

int sbk_image_seal_verify(const struct sbk_os_slot *slot)
{
        struct sbk_image_seal seal;
        struct sbk_image_info info;
        struct sbk_crypto_se seal_se = {
                .data = &seal_se,
        };
        uint8_t *hash = sbk_crypto_hash_from_seal(&seal_se);
        struct sbk_crypto_se hash_se = {
                .data = hash,
        };
        struct hash_read_ctx read_ctx = {
                .slot = slot,
        };
        uint32_t read_size;
        int rc;

        rc = sbk_os_slot_read(slot, 0U, &seal, sizeof(seal));
        if (rc != 0) {
                goto end;
        }
        rc = sbk_os_slot_read(slot, sizeof(seal), &info, sizeof(info));
        if (rc != 0) {
                goto end;
        }

        /* verify the manifest hash */
        read_ctx.offset = sizeof(seal);
        read_size = sizeof(seal);
        read_size += info.image_dep_cnt * sizeof(struct sbk_image_dep_info);
        read_size += info.device_dep_cnt * sizeof(struct sbk_device_dep_info);

        rc = sbk_crypto_hash_verify(&hash_se, hash_read_cb,
                                    (const void *)&read_ctx, read_size);
        if (rc != 0) {
                goto end;
        }

        /* verify the signature */
        rc = sbk_crypto_seal_verify(&seal_se);
end:
        return rc;
}

int sbk_image_hash_verify(const struct sbk_os_slot *slot)
{
        const uint32_t seal_size = sizeof(struct sbk_image_seal);
        struct sbk_image_info info;
        uint8_t *hash = &info.image_hash[0];
        struct sbk_crypto_se hash_se = {
                .data = hash,
        };
        struct hash_read_ctx read_ctx = {
                .slot = slot,
        };
        uint32_t read_size;
        int rc;

        rc = sbk_os_slot_read(slot, seal_size, &info, sizeof(info));
        if (rc != 0) {
                goto end;
        }

        /* verify the hash */
        read_ctx.offset = info.image_offset_in_slot;
        read_size = info.image_size;
        rc = sbk_crypto_hash_verify(&hash_se, hash_read_cb,
                                    (const void *)&read_ctx, read_size);
end:
        return rc;
}

int sbk_image_encrypted_hash_verify(const struct sbk_os_slot *slot)
{
        const uint32_t seal_size = sizeof(struct sbk_image_seal);
        struct sbk_image_info info;
        uint8_t *hash = &info.encrypted_image_hash[0];
        struct sbk_crypto_se hash_se = {
                .data = hash,
        };
        struct hash_read_ctx read_ctx = {
                .slot = slot,
        };
        uint32_t read_size;
        int rc;

        rc = sbk_os_slot_read(slot, seal_size, &info, sizeof(info));
        if (rc != 0) {
                goto end;
        }

        /* verify the hash */
        read_ctx.offset = info.image_offset_in_slot;
        read_size = info.image_size;
        rc = sbk_crypto_hash_verify(&hash_se, hash_read_cb,
                                    (const void *)&read_ctx, read_size);
end:
        return rc;
}

static int sbk_image_get_image_address(const struct sbk_os_slot *slot,
                                uint32_t *address)
{
        const uint32_t seal_size = sizeof(struct sbk_image_seal);
        struct sbk_image_info info;
        int rc;

        rc = sbk_os_slot_read(slot, seal_size, &info, sizeof(info));
        if (rc != 0) {
                goto end;
        }

        *address = info.image_jump_address;
end:
        return rc;
}

int sbk_image_bootable(const struct sbk_os_slot *slot, uint32_t *address)
{
        const struct sbk_version *dev_version = sbk_get_device_version();
        int rc;

        rc = sbk_image_seal_verify(slot);
        if (rc != 0) {
                goto end;
        }

        rc = sbk_image_device_verify(slot, sbk_get_device_uuid(), dev_version);
        if (rc != 0) {
                goto end;
        }

        rc = sbk_image_hash_verify(slot);
        if (rc != 0) {
                goto end;
        }

        rc = sbk_image_get_image_address(slot, address);
end:
        return rc;
}