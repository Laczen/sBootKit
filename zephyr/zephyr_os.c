#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/logging/log.h>
#include "sbk/sbk_slot.h"
#include "sbk/sbk_shell.h"

LOG_MODULE_REGISTER(sbk, CONFIG_SBK_LOG_LEVEL);

#define FLASH_OFFSET CONFIG_FLASH_BASE_ADDRESS
#define FLASH_BSIZE 0x20000

#define SLOT0_NODE		DT_NODELABEL(slot0_partition)
#define SLOT0_MTD               DT_MTD_FROM_FIXED_PARTITION(SLOT0_NODE)
#define SLOT0_DEVICE	        DEVICE_DT_GET(SLOT0_MTD)
#define SLOT0_OFFSET	        DT_REG_ADDR(SLOT0_NODE)
#define SLOT0_SIZE              DT_REG_SIZE(SLOT0_NODE)
#define SLOT1_NODE		DT_NODELABEL(slot1_partition)
#define SLOT1_MTD               DT_MTD_FROM_FIXED_PARTITION(SLOT1_NODE)
#define SLOT1_DEVICE	        DEVICE_DT_GET(SLOT1_MTD)
#define SLOT1_OFFSET	        DT_REG_ADDR(SLOT1_NODE)
#define SLOT1_SIZE              DT_REG_SIZE(SLOT1_NODE)

enum slot_type {UNKNOWN, FLASH_TYPE};

struct slot_ctx {
	const struct device *dev;
	enum slot_type type;
	uint32_t off;
	uint32_t size;
};

const struct slot_ctx slots[2] = {
	{
#ifdef CONFIG_FLASH
		.dev = SLOT0_DEVICE,
#endif
		.type = FLASH_TYPE,
		.off = SLOT0_OFFSET,
		.size = SLOT0_SIZE,
	},
	{
#ifdef CONFIG_FLASH
		.dev = SLOT1_DEVICE,
#endif
		.type = FLASH_TYPE,
		.off = SLOT1_OFFSET,
		.size = SLOT1_SIZE,
	}
};

static int read(const void *ctx, uint32_t off, void *data, size_t len)
{
	const struct slot_ctx *sctx = (const struct slot_ctx *)ctx;
	int rc = -EINVAL;

	if (sctx->type == FLASH_TYPE) {
		if (IS_ENABLED(CONFIG_FLASH)) {
			rc = flash_read(sctx->dev, sctx->off + off, data, len);
		} else {
			memcpy(data, (void *)(sctx->off + off), len);
			rc = 0;
		}
	}

	return rc;
}

static int prog(const void *ctx, uint32_t off, const void *data,
		size_t len)
{
	const struct slot_ctx *sctx = (const struct slot_ctx *)ctx;
	int rc = -EINVAL;

	if ((IS_ENABLED(CONFIG_FLASH)) && (sctx->type == FLASH_TYPE)) {
		if (((sctx->off + off) % 0x20000) == 0U) {
			rc = flash_erase(sctx->dev, sctx->off + off, 131072);
			if (rc != 0) {
				goto end;
			}
		}
		rc = flash_write(sctx->dev, sctx->off + off, data, len);
	}

end:
	return rc;
}

static int address(const void *ctx, uint32_t *address)
{
	const struct slot_ctx *sctx = (const struct slot_ctx *)ctx;
	int rc = -EINVAL;

	if (sctx->type == FLASH_TYPE) {
		*address += FLASH_OFFSET + sctx->off;
		rc = 0;
	}

	return rc;
}

static int size(const void *ctx, size_t *size)
{
	const struct slot_ctx *sctx = (const struct slot_ctx *)ctx;

	*size = sctx->size;
	return 0;
}

int sbk_open_bootable_slot(struct sbk_slot *slot, uint8_t idx)
{
	if (idx >= ARRAY_SIZE(slots)) {
		return -EINVAL;
	}

	slot->ctx = (void *)&slots[idx];
	slot->read = read;
	slot->prog = NULL;
	slot->close = NULL;
	slot->size = NULL;
	slot->address = address;
	return 0;
}

int sbk_open_destination_slot(struct sbk_slot *slot, uint8_t idx)
{
	int rc = sbk_open_bootable_slot(slot, idx);

	slot->prog = prog;
	slot->size = size;
	return rc;
}

int sbk_open_upload_slot(struct sbk_slot *slot, uint8_t idx)
{
	return sbk_open_destination_slot(slot, idx);
}

int sbk_open_backup_slot(struct sbk_slot *slot, uint8_t idx)
{
	return -EINVAL;
}

int sbk_open_shareddata_slot(struct sbk_slot *slot, uint8_t idx)
{
	return -EINVAL;
}

int sbk_open_key_slot(struct sbk_slot *slot, uint8_t idx)
{
	return -EINVAL;
}

/* change this to any other UART peripheral if desired */
#define UART_DEVICE_NODE DT_CHOSEN(zephyr_shell_uart)
static const struct device *const uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);


int serial_receive(const void *receive_ctx, unsigned char *c)
{
	const struct device *uart_dev = (const struct device *)receive_ctx;

	return uart_poll_in(uart_dev, c);
}

void serial_send(const void *send_ctx, unsigned char c)
{
	const struct device *uart_dev = (const struct device *)send_ctx;

	uart_poll_out(uart_dev, c);
}

int sbk_shell_init_transport(const struct sbk_shell *sh)
{
	if (!device_is_ready(uart_dev)) {
		return -ENODEV;
	}

	struct sbk_shell_data *sh_data = sh->data;

	sh_data->send_ctx = (void *)uart_dev;
	sh_data->send = serial_send;

	char c;
	while (serial_receive(uart_dev, &c) == 0);
	sh_data->receive_ctx = (void *)uart_dev;
	sh_data->receive = serial_receive;

	return 0;
}
