/*
 * TLV based manifest support for sbk
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SBK_TLV_MANIFEST_H_
#define SBK_TLV_MANIFEST_H_

#include "sbk/sbk_os.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @brief tlv manifest API
 * @{
 */

enum sbk_envelope_tags {
        SBK_TLV_ENVELOPE_SIGNATURE_ECDSA_TAG = 0x4500,  /* required, one */
        SBK_TLV_ENVELOPE_DIGEST_SHA256_TAG = 0x4510,    /* required, one */
        SBK_TLV_ENVELOPE_MANIFEST_TAG = 0x45FF,         /* required */
};

enum sbk_manifest_tags {
        SBK_TLV_MANIFEST_VERSION_TAG = 0x4D00,          /* required */
        SBK_TLV_MANIFEST_SEQUENCE_TAG = 0x4D01,         /* required */
        SBK_TLV_MANIFEST_VALIDITY_TAG = 0x4D02,         /* optional */
        SBK_TLV_MANIFEST_HARDWARE_TAG = 0x4D03,         /* required */
        SBK_TLV_MANIFEST_URI = 0x4D05,                  /* optional */
        SBK_TLV_MANIFEST_IMAGE_TAG = 0x4DFF,            /* required */
};

enum sbk_image_tags {
        SBK_TLV_IMAGE_SLOTNO_TAG = 0x4900,              /* required, unless 1 */
        SBK_TLV_IMAGE_SIZE = 0x4901,                    /* required */
        SBK_TLV_IMAGE_URI = 0x4902,                     /* optional */
        SBK_TLV_IMAGE_RUN_DIGEST_SHA256_TAG = 0x4910,   /* required, 1 of many*/
        SBK_TLV_IMAGE_PREP_DIGEST_SHA256_TAG = 0x4920,  /* required, one */
        SBK_TLV_IMAGE_KEY_KDF1_TAG = 0x4930,            /* optional */
};

/**
 * @brief sbk_tlv_manifest_open
 *
 * Open the newest manifest, does no check on manifest validity.
 *
 * @param manifest manifest to set
 * @retval 0 if no error, errorcode otherwise
 */
int sbk_tlv_manifest_open(struct sbk_os_slot *manifest);

/**
 * @brief sbk_tlv_manifest_close
 *
 * Close the manifest.
 *
 * @param manifest manifest to close
 * @retval 0 if no error, errorcode otherwise
 */
int sbk_tlv_manifest_close(struct sbk_os_slot *manifest);

/**
 * @brief sbk_tlv_manifest_switch
 *
 * Switch to the other manifest, does no check on manifest validity.
 * Requires an opened manifest.
 *
 * @param manifest manifest to set
 * @retval 0 if no error, errorcode otherwise
 */
int sbk_tlv_manifest_switch(struct sbk_os_slot *manifest);

/**
 * @brief sbk_tlv_manifest_clear
 *
 * Remove the manifest from storage.
 * Requires an opened manifest.
 *
 * @param manifest manifest to clear
 * @retval 0 if no error, errorcode otherwise
 */
int sbk_tlv_manifest_clear(struct sbk_os_slot *manifest);

/**
 * @brief sbk_tlv_manifest_valid
 *
 * Checks manifest validity.
 * Requires an opened manifest.
 *
 * @param manifest manifest to validate
 * @retval true is manifest is OK
 */
bool sbk_tlv_manifest_valid(const struct sbk_os_slot *manifest);

/**
 * @brief sbk_tlv_manifest_run_digest_valid
 *
 * Check if all images in run slots have a valid digest.
 *
 * @param manifest manifest to use in validation
 * @retval true if condition is OK
 */
bool sbk_tlv_manifest_run_digest_valid(const struct sbk_os_slot *manifest);

/**
 * @brief sbk_tlv_manifest_prep_digest_valid
 *
 * Check if all images have either a valid in run digest or a valid digest
 * for one of the 2 preparation slots (PREP0: backup, PREP1: new).
 *
 * @param manifest manifest to use in validation
 * @retval true if condition is OK
 */
bool sbk_tlv_manifest_prep_digest_valid(const struct sbk_os_slot *manifest);

/**
 * @brief sbk_tlv_manifest_is_test
 *
 * Check if the manifest is a test manifest. Test manifests can only be
 * started once and are removed on first boot. A test manifest can be
 * confirmed by writing a confirmed manifest while the image is running.
 *
 * @param manifest manifest to use in validation
 * @retval true if condition is OK
 */
bool sbk_tlv_manifest_is_test(const struct sbk_os_slot *manifest);

/**
 * @}
 */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SBK_TLV_MANIFEST_H_ */
