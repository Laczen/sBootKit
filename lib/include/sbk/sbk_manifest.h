/*
 * manifest support for sbk + wrapper to different backends
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SBK_MANIFEST_H_
#define SBK_MANIFEST_H_

#include "sbk/sbk_os.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @brief manifest API
 * @{
 */

/**
 * @brief sbk_manifest_epoch
 *
 * Get the manifest epoch, does no check on manifest validity.
 *
 * @param store location of the manifest
 * @retval epoch
 */

uint64_t sbk_manifest_epoch(struct sbk_os_slot *slot);

/**
 * @brief sbk_manifest_slot
 *
 * Get the manifest slot, does no check on manifest validity.
 *
 * @param store location of the manifest
 * @retval slot
 */

uint32_t sbk_manifest_slot(struct sbk_os_slot *slot);

/**
 * @brief sbk_manifest_valid
 *
 * Checks manifest validity.
 * Requires an opened manifest.
 *
 * @param manifest manifest to validate
 * @retval true is manifest is OK
 */
bool sbk_manifest_valid(const struct sbk_os_slot *manifest);

/**
 * @brief sbk_manifest_run_digest_valid
 *
 * Check validity of run digest in store.
 *
 * @param store store to use in validation
 * @retval true if condition is OK
 */
bool sbk_manifest_run_digest_valid(const struct sbk_os_slot *slot);

/**
 * @brief sbk_manifest_upl_digest_valid
 *
 * Check validity of upload digest in store.
 *
 * @param store store to use in validation
 * @retval true if condition is OK
 */
bool sbk_manifest_upl_digest_valid(const struct sbk_os_slot *slot);

/**
 * @brief sbk_manifest_is_test
 *
 * Check if the manifest is a test manifest. Test manifests can only be
 * started once and are removed on first boot. A test manifest can be
 * confirmed by writing a confirmed manifest while the image is running.
 *
 * @param store store to use in validation
 * @retval true if condition is OK
 */
bool sbk_manifest_is_test(const struct sbk_os_slot *slot);

/**
 * @}
 */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SBK_MANIFEST_H_ */
