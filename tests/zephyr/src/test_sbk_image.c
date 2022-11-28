/*
 * Copyright (c) 2019 Laczen
 * Copyright (c) 2017 Nordic Semiconductor ASA
 * Copyright (c) 2015 Runtime Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>

#include "sbk/sbk_board.h"
#include "sbk/sbk_image.h"
#include "sbk/sbk_os.h"

uint32_t board_id = 0xAABBCCDD;
struct sbk_version board_version = {
        .major = 0,
        .minor = 0,
        .revision = 0,
};

struct {
        struct sbk_image_meta_start image_meta_start;
        struct sbk_image_dep_info image_dep_info;
        struct sbk_board_dep_info board_dep_info;
        struct sbk_image_state image_state;
} image = {
        .image_meta_start = {
                .rec_hdr = {
                        .tag = 0x8000,
                        .len = sizeof(struct sbk_image_meta_start),
                },
                .image_dep_tag = 0x0001,
                .board_dep_tag = 0x0002,
                .image_state_tag = 0x8003,
                .next_tag = 0x7FFF,
        },
        .image_dep_info = {
                .rec_hdr = {
                        .tag = 0x0001,
                        .len = sizeof(struct sbk_image_dep_info),
                },
        },
        .board_dep_info = {
                .rec_hdr = {
                        .tag = 0x0002,
                        .len = sizeof(struct sbk_board_dep_info),
                },
                .board_id = 0xAABBCCDD,
        },
        .image_state = {
                .rec_hdr = {
                        .tag = 0x8003,
                        .len = sizeof(struct sbk_image_state),
                },
        },
};

ZTEST_SUITE(sbk_image_tests, NULL, NULL, NULL, NULL, NULL);

/**
 * @brief
 */
ZTEST(sbk_image_tests, sbk_image_get_tag)
{
        struct sbk_os_slot slot;
        struct sbk_image_meta_start start;
        struct sbk_image_dep_info img_dep_info;
        struct sbk_board_dep_info brd_dep_info;
        struct sbk_image_state img_state;
        int err;

        sbk_init_board_id(&board_id);
        sbk_init_board_version(&board_version);

        err = sbk_os_slot_open(&slot, 0);
        zassert_true(err == 0, "Failed slot open: [err %d]", err);

        err = sbk_os_slot_prog(&slot, 0U, &image, sizeof(image));
        zassert_true(err == 0, "Failed slot program: [err %d]", err);

        err = sbk_image_get_tag_data(&slot, 0x8000, &start, sizeof(start));
        zassert_true(err == 0, "Failed getting start tag: [err %d]", err);
        err = memcmp(&start, &image.image_meta_start, sizeof(start));
        zassert_true(err == 0, "Start tag contaings wrong value");

        err = sbk_image_get_tag_data(&slot, 0x0001, &img_dep_info,
                                     sizeof(img_dep_info));
        zassert_true(err == 0, "Failed getting image_dep_info: [err %d]", err);
        err = memcmp(&img_dep_info, &image.image_dep_info,
                     sizeof(img_dep_info));
        zassert_true(err == 0, "Image dep info tag contaings wrong value");

        err = sbk_image_get_tag_data(&slot, 0x0002, &brd_dep_info,
                                     sizeof(brd_dep_info));
        zassert_true(err == 0, "Failed getting board_dep_info: [err %d]", err);
        err = memcmp(&brd_dep_info, &image.board_dep_info,
                     sizeof(brd_dep_info));
        zassert_true(err == 0, "Board dep info tag contaings wrong value");

        err = sbk_image_get_tag_data(&slot, 0x8003, &img_state,
                                     sizeof(img_state));
        zassert_true(err == 0, "Failed getting image_state: [err %d]", err);
        err = memcmp(&img_state, &image.image_state, sizeof(img_state));
        zassert_true(err == 0, "Image state tag contaings wrong value");

        err = sbk_image_get_tag_data(&slot, 0x0003, &img_state,
                                     sizeof(img_state));
        zassert_false(err == 0, "Succeeded to get bad tag");

        err = sbk_os_slot_close(&slot);
        zassert_true(err == 0, "Failed slot close: [err %d]", err);
}

/*
 * @brief
 */
ZTEST(sbk_image_tests, sbk_board_dependency)
{
        struct sbk_os_slot slot;
        int err;

        sbk_init_board_id(&board_id);
        sbk_init_board_version(&board_version);

        err = sbk_os_slot_open(&slot, 0);
        zassert_true(err == 0, "Failed slot open: [err %d]", err);

        err = sbk_os_slot_prog(&slot, 0U, &image, sizeof(image));
        zassert_true(err == 0, "Failed slot program: [err %d]", err);

        err = sbk_image_board_verify(&slot);
        zassert_true(err == 0, "Failed board verify: [err %d]", err);

        /* set a unsupported board id */
        image.board_dep_info.board_id = board_id + 1U;

        err = sbk_os_slot_prog(&slot, 0U, &image, sizeof(image));
        zassert_true(err == 0, "Failed slot program: [err %d]", err);

        err = sbk_image_board_verify(&slot);
        zassert_false(err == 0, "Verify succeeded on bad board: [err %d]", err);

        /* reset the board id */
        image.board_dep_info.board_id = board_id;

        /* set a unsupported board range*/
        image.board_dep_info.vrange.min_version.major = 1U;
        image.board_dep_info.vrange.max_version.major = 1U;

        err = sbk_os_slot_prog(&slot, 0U, &image, sizeof(image));
        zassert_true(err == 0, "Failed slot program: [err %d]", err);

        err = sbk_image_board_verify(&slot);
        zassert_false(err == 0, "Verify succeeded on bad board version");

        /* reset the supported board range*/
        image.board_dep_info.vrange.min_version.major = 0U;
        image.board_dep_info.vrange.max_version.major = 0U;

        err = sbk_os_slot_close(&slot);
        zassert_true(err == 0, "Failed slot close: [err %d]", err);
}