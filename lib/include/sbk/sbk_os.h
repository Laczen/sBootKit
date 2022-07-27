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
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief slot interface definition
 * 
 */

struct sbk_os_slot {
        /* DATA */
        uint32_t ebsize;                /* erase-block size */
        uint32_t ebcnt;                 /* erase-block count */
        
        /* API */
        /* read from the run part of the slot (needs implementation) */
        int (*rread)(const struct sbk_os_slot *slot, uint32_t off, void *data,
                     uint32_t len);
        /* program the run part of the slot (needs implementation) 
         * on devices that require block erase the routine should erase a
         * block when the first byte is written
         */ 
        int (*rprog)(const struct sbk_os_slot *slot, uint32_t off,
                     const void *data, uint32_t len);
        /* read from the upgrade part of the slot (needs implementation) */
        int (*uread)(const struct sbk_os_slot *slot, uint32_t off, void *data,
                     uint32_t len);
        /* program the upgrade part of the slot, when this is not implemented
         * the bootloader will not copy existing firmware to the update slot.
         * on devices that require block erase the routine should erase a
         * block when the first byte is written
         */
        int (*uprog)(const struct sbk_os_slot *slot, uint32_t off,
                     const void *data, uint32_t len);
        /* close the slot */
        int (*close)(const struct sbk_os_slot *slot);
};

/**
 * @brief OS interface routines, need to be provided by os.
 * 
 */

/** sbk_os_get_slot: setup sbk_os_slot for usage by bootloader.
 * 
 */
extern struct sbk_os_slot *(*sbk_os_get_slot)(uint32_t slot_no);

/** sbk_os_get_slot_cnt: routine that returns the number of image slots.
 * 
 */
extern uint32_t (*sbk_os_get_slot_cnt)(void);

/** sbk_os_jump_image: routine to jump to a booteable image.
 * 
 */
extern const void (*sbk_os_jump_image)(uint32_t slot_no);

/**
 * @brief Log function definition (needs to be provided by os)
 * 
 */

/* log function */
extern const void (*sbk_os_log)(int level, const char *fmt, ...);

/**
 * @brief Enumerate log codes
 * 
 */
enum sbk_log_codes {
        SBK_LOG_LEVEL_OFF = 0,
        SBK_LOG_LEVEL_ERROR = 1,
        SBK_LOG_LEVEL_WARN = 1,
        SBK_LOG_LEVEL_INFO = 2,
        SBK_LOG_LEVEL_DEBUG = 3,

};

#ifndef SBK_LOG_LEVEL
#define SBK_LOG_LEVEL SBK_LOG_LEVEL_INFO
#endif

#define SBK_LOG_ERR(_fmt, ...) \
do { \
        if ((SBK_LOG_LEVEL >= SBK_LOG_LEVEL_ERROR) && (sbk_os_log != NULL)) { \
                sbk_os_log(SBK_LOG_LEVEL_ERROR, _fmt, __VA_ARGS__); \
        } \
} while (0)

#define SBK_LOG_WRN(_fmt, ...) \
do { \
        if ((SBK_LOG_LEVEL >= SBK_LOG_LEVEL_WARN) && (sbk_os_log != NULL)) { \
                sbk_os_log(SBK_LOG_LEVEL_WARN, _fmt, __VA_ARGS__); \
        } \
} while (0)

#define SBK_LOG_INF(_fmt, ...) \
do { \
        if ((SBK_LOG_LEVEL >= SBK_LOG_LEVEL_INFO) && (sbk_os_log != NULL)) { \
                sbk_os_log(SBK_LOG_LEVEL_INFO, _fmt, __VA_ARGS__); \
        } \
} while (0)

#define SBK_LOG_DBG(_fmt, ...) \
do { \
        if ((SBK_LOG_LEVEL >= SBK_LOG_LEVEL_DEBUG) && (sbk_os_log != NULL)) { \
                sbk_os_log(SBK_LOG_LEVEL_DEBUG, _fmt, __VA_ARGS__); \
        } \
} while (0)

/**
 * @brief Interface routines to read/write used by bootloader.
 * 
 */
int sbk_os_slot_open(struct sbk_os_slot *slot, uint32_t slot_no);

int sbk_os_slot_close(const struct sbk_os_slot *slot);

int sbk_os_slot_rread(const struct sbk_os_slot *slot, uint32_t off,
                      void *data, uint32_t len);

int sbk_os_slot_rprog(const struct sbk_os_slot *slot, uint32_t off,
                      const void *data, uint32_t len);

int sbk_os_slot_uread(const struct sbk_os_slot *slot, uint32_t off,
                      void *data, uint32_t len);

int sbk_os_slot_uprog(const struct sbk_os_slot *slot, uint32_t off,
                      const void *data, uint32_t len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SBK_H_ */
