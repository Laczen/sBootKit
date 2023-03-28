/*
 * uart implementation
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/device.h>

/**
 * @brief Uart handling
 * 
 */
struct uart_handle {
        const struct device *dev;
        struct ring_buf *rb;
        struct k_work rx_work;
        void (*rx_cb)(const void *rx_cb_ctx, const char *data, size_t len);         
        void *rx_cb_ctx;
};

#define UART_HANDLE_DECLARE(_name, _dev, _rbsize)                              \
        RING_BUF_DECLARE(_name##_rx_rb, _rbsize);                              \
        static struct uart_handle _name = {                                    \
                .dev = _dev,                                                   \
                .rb = &_name##_rx_rb,                                          \
        };

void uart_handle_register_rx_cb(struct uart_handle *uhndl,
                                void (*rx_cb)(const void *rx_cb_ctx,
                                              const char *data, size_t len),
                                void *rx_cb_ctx);

void uart_handle_tx(const void *ctx, char c);

void uart_handle_start(struct uart_handle *uhndl);
