/*
 * configuration for sbootkit (routines to be provided by os)
 *
 * Copyright (c) 2021 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SBK_OS_H_
#define SBK_OS_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief slot interface definition
 *
 */

struct sbk_os_slot {
        /* opaque context pointer */
        void *ctx;

        /* read from the slot (needs implementation) */
        int (*read)(const void *ctx, uint32_t off, void *data, uint32_t len);

        /* program to the slot (needs implementation), on devices that
         * require block erase the routine should erase a block when the first
         * byte is written.
         */
        int (*prog)(const void *ctx, uint32_t off, const void *data, uint32_t len);

        /* sync the slot (needs implementation) */
        int (*sync)(const void *ctx);

        /* get the slot start address (needs implementation) */
        uint32_t (*get_start_address)(const void *ctx);

        /* get the slot size (needs implementation) */
        uint32_t (*get_size)(const void *ctx);
};

/** @brief sbk_os_slot_init, needs to be provided by os
 *
 * setup sbk_os_slot for usage by bootloader.
 *
 */
extern int (*sbk_os_slot_init)(struct sbk_os_slot *slot, uint32_t slot_no);

/**
 * @brief Interface routines to read/write slots used by bootloader.
 *
 */

/**
 * @brief sbk_os_slot_open
 *
 * open a slot (calls sbk_os_slot_init()), initializes slot
 */
int sbk_os_slot_open(struct sbk_os_slot *slot, uint32_t slot_no);

/**
 * @brief sbk_os_slot_read
 *
 * read from a slot
 */
int sbk_os_slot_read(const struct sbk_os_slot *slot, uint32_t off,
                     void *data, uint32_t len);

/**
 * @brief sbk_os_slot_program
 *
 * programs to a slot
 */
int sbk_os_slot_prog(const struct sbk_os_slot *slot, uint32_t off,
                     const void *data, uint32_t len);

/**
 * @brief sbk_os_slot_close
 *
 * closes a slot and ensures all data is written
 */
int sbk_os_slot_close(const struct sbk_os_slot *slot);


/**
 * @brief crypto interface definitions
 *
 */

struct sbk_os_crypto_digest {
        uint32_t type;  /* digest type */
        uint32_t size;  /* digest size */
        uint8_t *digest; /* digest */
};

/**
 * @brief sbk_os_crypto_digest_verify, needs to be provided by os.
 *
 */
extern int (*sbk_os_crypto_digest_verify)(
        const struct sbk_os_crypto_digest *digest,
        int (*read_cb)(const void *read_cb_ctx, uint32_t offset, void *data,
                       uint32_t len),
        const void *read_cb_ctx, uint32_t len);

struct sbk_os_crypto_signature {
        uint32_t type;  /* signature type */
        uint32_t size;  /* signature size */
        uint8_t *signature; /* pubkey and signature */
};
/**
 * @brief sbk_os_crypto_signature_verify, needs to be provided by os.
 *
 */
extern int (*sbk_os_crypto_signature_verify)(
        const struct sbk_os_crypto_signature *signature,
        int (*read_cb)(const void *read_cb_ctx, uint32_t offset, void *data,
                       uint32_t len),
        const void *read_cb_ctx, uint32_t len);

struct sbk_os_crypto_kx_in {
        uint32_t type;
        uint32_t size;
        uint8_t *data;
};

struct sbk_os_crypto_kx_out {
        uint32_t key_size;
        uint8_t *key;
        uint32_t nonce_size;
        uint8_t *nonce;
};

/**
 * @brief sbk_os_crypto_kx, needs to be provided by os.
 *
 * Key exchange routine
 *
 */
extern int (*sbk_os_crypto_kx)(const struct sbk_os_crypto_kx_in *kx_in,
                               const uint8_t *prkey, uint32_t prkey_size,
                               struct sbk_os_crypto_kx_out *kx_out);

struct sbk_os_crypto_crypt_ctx {
        uint32_t key_size;
        uint8_t *key;
        uint32_t nonce_size;
        uint8_t *nonce;
        uint32_t pos;
};

/**
 * @brief sbk_os_crypto_crypt_init, needs to be provided by os.
 *
 * Initialise encrypt/decrypt context
 *
 */
extern int (*sbk_os_crypto_crypt_init)()


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SBK_H_ */
