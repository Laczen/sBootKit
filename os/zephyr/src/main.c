/*
 * Copyright (c) 2021 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include "sbk/sbk_cfg.h"

int read(const struct sbk_cfg *cfg, const struct sbk_blk *blk, void *data, uint32_t len)
{
        return 0;
}

int prog(const struct sbk_cfg *cfg, const struct sbk_blk *blk, const void *data, uint32_t len)
{
        return 0;
}

int get_size(const struct sbk_cfg *cfg, const struct sbk_blk *blk, uint32_t *size)
{
        return 0;
}

uint32_t get_sector_size(const struct sbk_cfg *cfg)
{
        return 1024;
}

uint32_t get_image_count(const struct sbk_cfg *cfg)
{
        return 1;
}

void jump_image(const struct sbk_cfg *cfg)
{

}

        /* start execution of image in recovery slot (if available) */
void jump_recovery_image(const struct sbk_cfg *cfg)
{

}

SBK_REGISTER_CFG(NULL, read, prog, get_size, get_sector_size, get_image_count,
                 jump_image, jump_recovery_image);

void sbk_log(int level, const char *fmt, ...)
{
        va_list ap;
        va_start(ap, fmt);
        va_end(ap);
}

void (*sbk_log_fp)(int level, const char *fmt, ...) = NULL;

void main(void)
{

}