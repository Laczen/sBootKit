#include <zephyr/drivers/uart.h>

#include "uart_handle.h"

static void uart_irq_callback(const struct device *dev, void *user_data)
{
        struct uart_handle *uhndl = (struct uart_handle *)user_data;

	uart_irq_update(dev);

	if (!uart_irq_rx_ready(dev)) {
		return;
	}

        uint8_t *data;
        size_t len, rd_len;
        bool new_data = false;

        do {
                len = ring_buf_put_claim(uhndl->rb, &data, uhndl->rb->size);
		if (len > 0) {
			rd_len = uart_fifo_read(dev, data, len);
                        new_data = true;
			int err = ring_buf_put_finish(uhndl->rb, rd_len);
			(void)err;
		} else {
			uint8_t dummy;

			/* No space in the ring buffer - consume byte. */
			//LOG_WRN("RX ring buffer full.");
			rd_len = uart_fifo_read(dev, &dummy, 1);
		}
	} while (rd_len && (rd_len == len));

        if (new_data) {
                /* add task to workqueue */
                k_work_submit(&uhndl->rx_work);

        }
}

void uart_handle_register_rx_cb(struct uart_handle *uhndl,
                                void (*rx_cb)(const void *rx_cb_ctx,
                                              const char *data, size_t len),
                                void *rx_cb_ctx)
{
        uhndl->rx_cb = rx_cb;
        uhndl->rx_cb_ctx = rx_cb_ctx;
}

void uart_handle_tx(const void *ctx, char c)
{
        const struct uart_handle *uhndl = (const struct uart_handle *)ctx;

        uart_poll_out(uhndl->dev, c);
}

void uart_handle_process_rx_queue(struct k_work *work)
{
        struct uart_handle *uhndl = CONTAINER_OF(work, struct uart_handle, rx_work);
        const uint8_t *data;
        size_t len;
                        
        len = ring_buf_get_claim(uhndl->rb, (uint8_t **)&data, uhndl->rb->size);
        if (uhndl->rx_cb != NULL) {
                uhndl->rx_cb(uhndl->rx_cb_ctx, data, len);
        }
        ring_buf_get_finish(uhndl->rb, len);
}

void uart_handle_start(struct uart_handle *uhndl)
{

        k_work_init(&uhndl->rx_work, uart_handle_process_rx_queue);

        ring_buf_reset(uhndl->rb);
        uart_irq_callback_user_data_set(uhndl->dev, uart_irq_callback,
                                        (void *)uhndl);
        /* Drain the fifo */
	if (uart_irq_rx_ready(uhndl->dev)) {
		uint8_t c;

		while (uart_fifo_read(uhndl->dev, &c, 1));
	}

	uart_irq_rx_enable(uhndl->dev);
}