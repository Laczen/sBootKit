/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <zephyr/sys/printk.h>
#include <zephyr/kernel.h>
#include "mincrypt_test/crypto_sha256_tvectors.h"
#include "mincrypt_test/crypto_chacha20poly1305_tvectors.h"

void tst_crypto_sha256(void)
{
        size_t cnt = crypto_sha256_testcnt();
        for (size_t i = 0; i < cnt; ++i) {
                if (crypto_sha256_test(i) != 0) {
                        printk("sha256 test %d failed\n", i + 1);
                        return;
                }
        }

        printk("sha256 passed %d tests\n", cnt);
}

void tst_crypto_hmac_sha256(void)
{
        size_t cnt = crypto_hmac_sha256_testcnt();
        for (size_t i = 0; i < cnt; ++i) {
                if (crypto_hmac_sha256_test(i) != 0) {
                        printk("hmac_sha256 test %d failed\n", i + 1);
                        return;
                }
        }

        printk("hmac_sha256 passed %d tests\n", cnt);
}

void tst_crypto_hkdf_sha256(void)
{
        size_t cnt = crypto_hkdf_sha256_testcnt();
        for (size_t i = 0; i < cnt; ++i) {
                if (crypto_hkdf_sha256_test(i) != 0) {
                        printk("hkdf_sha256 test %d failed\n", i + 1);
                        return;
                }
        }

        printk("hkdf_sha256 passed %d tests\n", cnt);
}

void tst_crypto_poly1305(void)
{
        size_t cnt = crypto_poly1305_testcnt();
        for (size_t i = 0; i < cnt; ++i) {
                if (crypto_poly1305_test(i) != 0) {
                        printk("poly1305 test %d failed\n", i + 1);
                        return;
                }
        }

        printk("poly1305 passed %d tests\n", cnt);
}

void tst_crypto_chacha20(void)
{
        size_t cnt = crypto_chacha20_testcnt();
        for (size_t i = 0; i < cnt; ++i) {
                if (crypto_chacha20_test(i) != 0) {
                        printk("chacha20 test %d failed\n", i + 1);
                        return;
                }
        }

        printk("chacha20 passed %d tests\n", cnt);
}

void main(void)
{
        tst_crypto_sha256();
        tst_crypto_hmac_sha256();
        tst_crypto_hkdf_sha256();
        tst_crypto_poly1305();
        tst_crypto_chacha20();
        printk("Done\n");
}