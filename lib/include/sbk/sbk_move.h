/*
 * Moving images to correct location for sbk
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SBK_MOVE_H_
#define SBK_MOVE_H_

#include "sbk/sbk_os.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @brief sbk_move API structures
 * @{
 */

int sbk_move(void);

int sbk_move_manifest(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SBK_MOVE_H_ */
