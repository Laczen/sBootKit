/*
 * Copyright (c) 2021 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ztest.h>
#include "sbk/sbk_tlv.h"

uint8_t test_haystack[] = {
        1,0,2,0, 1,2, 	/* type = 1, length = 2, value = 1 2 */
        2,0,3,0, 3,4,5, /* type = 2, length = 3, value = 3 4 5 */
        3,0,1,0, 6,	/* type = 3, length = 1, value = 6 */
        4,0,26,0,       /* type = 4, length = 26, set of tlv's */
                1,0,2,0, 1,2, 	/* type = 1, length = 2, value = 1 2 */
                2,0,3,0, 3,4,5, /* type = 2, length = 3, value = 3 4 5 */
                3,0,1,0, 6,	/* type = 3, length = 1, value = 6 */
                0,1,2,0, 7,8,	/* type = 0x10, length = 1, value = 7 8 */
                0,0,		/* end the tlv area with a type zero */ 
        0,1,2,0, 7,8,	/* type = 0x10, length = 2, value = 7 8 */
        0,0		/* end the tlv area with a type zero */
};

struct tlv_rd_ctx {
        uint8_t *buffer;
        uint32_t buffer_size;
};

int tlv_read(const void *ctx, uint32_t offset, void *data, uint32_t len)
{
        struct tlv_rd_ctx *rd_ctx = (struct tlv_rd_ctx *)ctx;

        if ((offset + len) > rd_ctx->buffer_size) {
                return -1;
        }

        memcpy(data, rd_ctx->buffer + offset, len);
        return 0;
}

void test_tlv(void)
{
        int err;
        struct tlv_rd_ctx rd_ctx = {
                .buffer = test_haystack,
                .buffer_size = sizeof(test_haystack)
        };
        struct tlv_rd_ctx rd_ctx_sub;
        struct sbk_tlv_entry entry, sub_entry;
        uint8_t buf[sizeof(test_haystack)];

        /* Program the haystack */
        
        sbk_tlv_walk_init(&entry);
        while ((sbk_tlv_walk(&entry, &tlv_read, (void *)&rd_ctx) == 0) && 
               (entry.hdr.tag != 0x01)) {
        }
        
        memset(buf, 0xff, sizeof(buf));
        zassert_true(entry.hdr.tag == 1, "Entry type 1 not found");
        zassert_true(entry.hdr.len == 2, "Entry type 1 wrong length");
        tlv_read((void *)&rd_ctx, entry.offset, buf, entry.hdr.len);
        err = memcmp(&test_haystack[4], buf, entry.hdr.len);
        zassert_true(err == 0, "Entry type 1 wrong value %d");

        sbk_tlv_walk_init(&entry);
        while ((sbk_tlv_walk(&entry, &tlv_read, (void *)&rd_ctx) == 0) && 
               (entry.hdr.tag != 0x02)) {
        }
        
        memset(buf, 0xff, sizeof(buf));
        zassert_true(entry.hdr.tag == 2, "Entry type 2 not found");
        zassert_true(entry.hdr.len == 3, "Entry type 2 wrong length");
        tlv_read((void *)&rd_ctx, entry.offset, buf, entry.hdr.len);
        err = memcmp(&test_haystack[10], buf, entry.hdr.len);
        zassert_true(err == 0, "Entry type 2 wrong value %d");

        sbk_tlv_walk_init(&entry);
        while ((sbk_tlv_walk(&entry, &tlv_read, (void *)&rd_ctx) == 0) && 
               (entry.hdr.tag != 0x03)) {
        }
        
        memset(buf, 0xff, sizeof(buf));
        zassert_true(entry.hdr.tag == 3, "Entry type 3 not found");
        zassert_true(entry.hdr.len == 1, "Entry type 3 wrong length");
        tlv_read((void *)&rd_ctx, entry.offset, buf, entry.hdr.len);
        err = memcmp(&test_haystack[17], buf, entry.hdr.len);
        zassert_true(err == 0, "Entry type 3 wrong value %d");

        sbk_tlv_walk_init(&entry);
        while ((sbk_tlv_walk(&entry, &tlv_read, (void *)&rd_ctx) == 0) && 
               (entry.hdr.tag != 256)) {
        }
        
        memset(buf, 0xff, sizeof(buf));
        zassert_true(entry.hdr.tag == 256, "Entry type 256 not found");
        zassert_true(entry.hdr.len == 2, "Entry type 256 wrong length");
        tlv_read((void *)&rd_ctx, entry.offset, buf, entry.hdr.len);
        err = memcmp(&test_haystack[52], buf, entry.hdr.len);
        zassert_true(err == 0, "Entry type 256 wrong value %d");

        sbk_tlv_walk_init(&entry);
        while ((sbk_tlv_walk(&entry, &tlv_read, (void *)&rd_ctx) == 0) && 
               (entry.hdr.tag != 0x05)) {
        }
        zassert_false(entry.hdr.tag == 5, "Found non existing entry type 5");

        sbk_tlv_walk_init(&entry);
        while ((sbk_tlv_walk(&entry, &tlv_read, (void *)&rd_ctx) == 0) && 
               (entry.hdr.tag != 0x04)) {
        }
        zassert_true(entry.hdr.tag == 4, "Entry type 4 not found");
        zassert_true(entry.hdr.len == 26, "Entry type 4 wrong length");

        rd_ctx_sub.buffer = &test_haystack[entry.offset];
        rd_ctx_sub.buffer_size = sizeof(test_haystack) - entry.offset;
        sbk_tlv_walk_init(&sub_entry);
        while ((sbk_tlv_walk(&sub_entry, &tlv_read, (void *)&rd_ctx_sub) == 0) && 
               (sub_entry.hdr.tag != 0x03)) {
        }
        zassert_true(sub_entry.hdr.tag == 3, "Sub entry type 3 not found");
        zassert_true(sub_entry.hdr.len == 1, "Sub entry type 3 wrong length");

}

void test_sbk_tlv(void)
{
        ztest_test_suite(test_sbk_tlv,
	        ztest_unit_test(test_tlv)
        );

	ztest_run_test_suite(test_sbk_tlv);
}
