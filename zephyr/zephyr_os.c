#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/logging/log.h>
#include "sbk/sbk_slot.h"
#include "sbk/sbk_shell.h"

LOG_MODULE_REGISTER(zephyr_os, CONFIG_SBK_LOG_LEVEL);

#define FLASH_OFFSET CONFIG_FLASH_BASE_ADDRESS

#define SLDR_NODE      DT_NODELABEL(sldr_partition)
#define SLDR_MTD       DT_MTD_FROM_FIXED_PARTITION(SLDR_NODE)
#define SLDR_DEVICE    DEVICE_DT_GET(SLDR_MTD)
#define SLDR_OFFSET    DT_REG_ADDR(SLDR_NODE)
#define SLDR_SIZE      DT_REG_SIZE(SLDR_NODE)
#define IMAGE0_NODE    DT_NODELABEL(image0_partition)
#define IMAGE0_MTD     DT_MTD_FROM_FIXED_PARTITION(IMAGE0_NODE)
#define IMAGE0_DEVICE  DEVICE_DT_GET(IMAGE0_MTD)
#define IMAGE0_OFFSET  DT_REG_ADDR(IMAGE0_NODE)
#define IMAGE0_SIZE    DT_REG_SIZE(IMAGE0_NODE)
#define UPDATE0_NODE   DT_NODELABEL(update0_partition)
#define UPDATE0_MTD    DT_MTD_FROM_FIXED_PARTITION(UPDATE0_NODE)
#define UPDATE0_DEVICE DEVICE_DT_GET(UPDATE0_MTD)
#define UPDATE0_OFFSET DT_REG_ADDR(UPDATE0_NODE)
#define UPDATE0_SIZE   DT_REG_SIZE(UPDATE0_NODE)
#define BACKUP0_NODE   DT_NODELABEL(backup0_partition)
#define BACKUP0_MTD    DT_MTD_FROM_FIXED_PARTITION(BACKUP0_NODE)
#define BACKUP0_DEVICE DEVICE_DT_GET(BACKUP0_MTD)
#define BACKUP0_OFFSET DT_REG_ADDR(BACKUP0_NODE)
#define BACKUP0_SIZE   DT_REG_SIZE(BACKUP0_NODE)

enum slot_type {
	UNKNOWN,
	FLASH_TYPE
};

struct slot_ctx {
	const struct device *dev;
	enum slot_type type;
	uint32_t off;
	uint32_t size;
};

static int read(const void *ctx, uint32_t off, void *data, size_t len)
{
	const struct slot_ctx *sctx = (const struct slot_ctx *)ctx;
	int rc = -EINVAL;

	if ((len > sctx->size) || (off > (sctx->size - len))) {
		goto end;
	}

	if (sctx->type == FLASH_TYPE) {
		if (IS_ENABLED(CONFIG_FLASH)) {
			rc = flash_read(sctx->dev, sctx->off + off, data, len);
		} else {
			memcpy(data, (void *)(FLASH_OFFSET + sctx->off + off),
			       len);
			rc = 0;
		}
	}

end:
	return rc;
}

static int prog(const void *ctx, uint32_t off, const void *data, size_t len)
{
	const struct slot_ctx *sctx = (const struct slot_ctx *)ctx;
	int rc = -EINVAL;

	if ((len > sctx->size) || (off > (sctx->size - len))) {
		goto end;
	}

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

const struct slot_ctx sldr_ctx = {
#ifdef CONFIG_FLASH
	.dev = SLDR_DEVICE,
#endif
	.type = FLASH_TYPE,
	.off = SLDR_OFFSET,
	.size = SLDR_SIZE,
};

int sbk_open_sldr_slot(struct sbk_slot *slot)
{
	LOG_DBG("Opening secure loader slot at %x size %d", sldr_ctx.off,
		sldr_ctx.size);
	slot->ctx = (void *)&sldr_ctx;
	slot->read = read;
	slot->prog = prog;
	slot->close = NULL;
	slot->size = size;
	slot->address = address;
	return 0;
}

const struct slot_ctx image_ctx[1] = {{
#ifdef CONFIG_FLASH
	.dev = IMAGE0_DEVICE,
#endif
	.type = FLASH_TYPE,
	.off = IMAGE0_OFFSET,
	.size = IMAGE0_SIZE,
}};

int sbk_open_image_slot(struct sbk_slot *slot, uint8_t idx)
{
	if (idx >= 1) {
		return -EINVAL;
	}

	LOG_DBG("Opening image slot at %x size %d", image_ctx[idx].off,
		image_ctx[idx].size);
	slot->ctx = (void *)&image_ctx[idx];
	slot->read = read;
	slot->prog = prog;
	slot->close = NULL;
	slot->size = size;
	slot->address = address;
	return 0;
}

int sbk_open_rimage_slot(struct sbk_slot *slot, uint8_t idx)
{
	int rc = sbk_open_image_slot(slot, idx);
	slot->prog = NULL;
	return rc;
}

const struct slot_ctx update_ctx[1] = {{
#ifdef CONFIG_FLASH
	.dev = UPDATE0_DEVICE,
#endif
	.type = FLASH_TYPE,
	.off = UPDATE0_OFFSET,
	.size = UPDATE0_SIZE,
}};

int sbk_open_update_slot(struct sbk_slot *slot, uint8_t idx)
{
	if (idx >= 1) {
		return -EINVAL;
	}

	LOG_DBG("Opening update slot at %x size %d", update_ctx[idx].off,
		update_ctx[idx].size);
	slot->ctx = (void *)&update_ctx[idx];
	slot->read = read;
	slot->prog = prog;
	slot->close = NULL;
	slot->size = size;
	slot->address = address;
	return 0;
}

const struct slot_ctx backup_ctx[1] = {{
#ifdef CONFIG_FLASH
	.dev = BACKUP0_DEVICE,
#endif
	.type = FLASH_TYPE,
	.off = BACKUP0_OFFSET,
	.size = BACKUP0_SIZE,
}};

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
	while (serial_receive(uart_dev, &c) == 0)
		;
	sh_data->receive_ctx = (void *)uart_dev;
	sh_data->receive = serial_receive;

	return 0;
}
