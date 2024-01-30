#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/logging/log.h>
#include <zephyr/linker/devicetree_regions.h>
#include "sbk/sbk_slot.h"
#include "sbk/sbk_shell.h"
#include "zephyr_os.h"

LOG_MODULE_REGISTER(zephyr_os, CONFIG_SBK_LOG_LEVEL);

#define IFLASH_OFFSET  DT_REG_ADDR(DT_INST(0, soc_nv_flash))
//#define IFLASH_OFFSET 0x80000000

enum slot_type {
	UNKNOWN,
	FLASH_TYPE,
};

struct slot_flash_backend {
	const struct device *dev;
	const uint32_t off;
	size_t erase_block_size;
	size_t write_block_size;
};
struct slot_ctx {
	const void *backend;
	const enum slot_type type;
	const size_t size;
};

static int read(const void *ctx, uint32_t off, void *data, size_t len)
{
	const struct slot_ctx *sctx = (const struct slot_ctx *)ctx;
	int rc = -EINVAL;

	if ((len > sctx->size) || (off > (sctx->size - len))) {
		goto end;
	}

	if (IS_ENABLED(CONFIG_SBK_IS_SFSL) && !IS_ENABLED(CONFIG_FLASH)) {
		const struct slot_flash_backend *fb =
			(const struct slot_flash_backend *)sctx->backend;

		memcpy(data, (void *)(IFLASH_OFFSET + fb->off + off), len);
		rc = 0;
	}

	if (IS_ENABLED(CONFIG_FLASH) && (sctx->type == FLASH_TYPE)) {
		const struct slot_flash_backend *fb =
			(const struct slot_flash_backend *)sctx->backend;

		rc = flash_read(fb->dev, fb->off + off, data, len);
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

	if (IS_ENABLED(CONFIG_FLASH) && (sctx->type == FLASH_TYPE)) {
		const struct slot_flash_backend *fb =
			(const struct slot_flash_backend *)sctx->backend;
		const size_t ebs = fb->erase_block_size;

		if (((off % ebs) == 0U) &&
		    (flash_erase(fb->dev, fb->off + off, ebs) == 0)) {
			rc = flash_write(fb->dev, fb->off + off, data, len);
		}
	}

end:
	return rc;
}

static int ioctl(const void *ctx, enum sbk_slot_ioctl_cmd cmd, void *data,
		 size_t len)
{
	const struct slot_ctx *sctx = (const struct slot_ctx *)ctx;
	int rc = -ENOTSUP;

	switch (cmd) {
	case SBK_SLOT_IOCTL_GET_SIZE:
		if ((len != sizeof(size_t)) || (data == NULL)) {
			rc = -EINVAL;
			break;
		}

		size_t *size = (size_t *)data;

		*size = sctx->size;
		rc = 0;
		break;

	case SBK_SLOT_IOCTL_GET_ADDRESS:
		if ((len != sizeof(uint32_t)) || (data == NULL)) {
			rc = -EINVAL;
			break;
		}

		if (sctx->type == FLASH_TYPE) {
			const struct slot_flash_backend *fb =
				(const struct slot_flash_backend *)sctx->backend;
			uint32_t *address = (uint32_t *)data;

			*address += IFLASH_OFFSET + fb->off;
			LOG_DBG("Address 0x%x", *address);
			rc = 0;
		}

		break;

	case SBK_SLOT_IOCTL_GET_ERASE_BLOCK_SIZE:
		if ((len != sizeof(uint32_t)) || (data == NULL)) {
			rc = -EINVAL;
			break;
		}

		if (sctx->type == FLASH_TYPE) {
			const struct slot_flash_backend *fb =
				(const struct slot_flash_backend *)sctx->backend;
			uint32_t *ebs = (uint32_t *)data;

			*ebs = fb->erase_block_size;
			rc = 0;
		}

		break;
	case SBK_SLOT_IOCTL_GET_WRITE_BLOCK_SIZE:
		if ((len != sizeof(uint32_t)) || (data == NULL)) {
			rc = -EINVAL;
			break;
		}

		if (sctx->type == FLASH_TYPE) {
			const struct slot_flash_backend *fb =
				(const struct slot_flash_backend *)sctx->backend;
			uint32_t *wbs = (uint32_t *)data;

			*wbs = fb->write_block_size;
			rc = 0;
		}
		break;
	default:
		break;
	}

	return rc;
}

static int close(const void *ctx)
{
	return 0;
}

void open_slot(struct sbk_slot *slot)
{
	slot->read = read;
	slot->prog = IS_ENABLED(CONFIG_SBK_IS_SFSL) ? NULL : prog;
	slot->ioctl = ioctl;
	slot->close = close;
}

const struct slot_flash_backend sldr_backend = {
	.off = GET_PARTITION_OFFSET(sldr_partition),
	.erase_block_size = GET_PARTITION_EBS(sldr_partition),
	.write_block_size = GET_PARTITION_WBS(sldr_partition),
	.dev = GET_PARTITION_DEV(sldr_partition),
};

const struct slot_ctx sldr_slot_ctx = {
	.backend = (void *)&sldr_backend,
	.size = GET_PARTITION_SIZE(sldr_partition),
	.type = FLASH_TYPE,
};

const struct slot_flash_backend productdata_backend = {
	.off = GET_PARTITION_OFFSET(productdata_partition),
	.erase_block_size = 0,
	.write_block_size = 0,
	.dev = GET_PARTITION_DEV(productdata_partition),
};

const struct slot_ctx productdata_slot_ctx = {
	.backend = (void *)&productdata_backend,
	.size = GET_PARTITION_SIZE(productdata_partition),
	.type = FLASH_TYPE,
};

const struct slot_flash_backend image_backends[] = {
	{
		.off = GET_PARTITION_OFFSET(image0_partition),
		.erase_block_size = GET_PARTITION_EBS(image0_partition),
		.write_block_size = GET_PARTITION_WBS(image0_partition),
		.dev = GET_PARTITION_DEV(image0_partition),
	},
	{
		.off = GET_PARTITION_OFFSET(update0_partition),
		.erase_block_size = GET_PARTITION_EBS(update0_partition),
		.write_block_size = GET_PARTITION_WBS(update0_partition),
		.dev = GET_PARTITION_DEV(update0_partition),
	},
	{
		.off = GET_PARTITION_OFFSET(backup0_partition),
	 	.erase_block_size = GET_PARTITION_EBS(backup0_partition),
	 	.write_block_size = GET_PARTITION_WBS(sldr_partition),
	 	.dev = GET_PARTITION_DEV(backup0_partition)
	},
};

const struct slot_ctx image_slot_ctx[] = {
	{
		.backend = (void *)&image_backends[0],
		.size = GET_PARTITION_SIZE(image0_partition),
		.type = FLASH_TYPE,
	},
	{
		.backend = (void *)&image_backends[1],
		.size = GET_PARTITION_SIZE(update0_partition),
		.type = FLASH_TYPE,
	},
	{
		.backend = (void *)&image_backends[2],
		.size = GET_PARTITION_SIZE(backup0_partition),
		.type = FLASH_TYPE,
	}
};

int sbk_open_sldr_slot(struct sbk_slot *slot)
{
	open_slot(slot);
	slot->ctx = (void *)&sldr_slot_ctx;
	return 0;
}

int sbk_open_productdata_slot(struct sbk_slot *slot)
{
	open_slot(slot);
	slot->prog = NULL;
	slot->ctx = (void *)&productdata_slot_ctx;
	return 0;
}

int sbk_open_pubkey_slot(struct sbk_slot *slot)
{
	return sbk_open_sldr_slot(slot);
}

int sbk_open_image_slot(struct sbk_slot *slot, uint32_t idx)
{
	if (idx >= 1) {
		return -EINVAL;
	}

	open_slot(slot);
	slot->ctx = (void *)&image_slot_ctx[0];
	return 0;
}

int sbk_open_rimage_slot(struct sbk_slot *slot, uint32_t idx)
{
	int rc = sbk_open_image_slot(slot, idx);
	slot->prog = NULL;
	return rc;
}

int sbk_open_update_slot(struct sbk_slot *slot, uint32_t idx)
{
	if (idx >= 1) {
		return -EINVAL;
	}

	open_slot(slot);
	slot->ctx = (void *)&image_slot_ctx[1];
	return 0;
}

int sbk_open_backup_slot(struct sbk_slot *slot, uint32_t idx)
{
	if (idx >= 1) {
		return -EINVAL;
	}

	open_slot(slot);
	slot->ctx = (void *)&image_slot_ctx[2];
	return 0;
}

#define BL_SHARED_SRAM_NODE DT_NODELABEL(bl_shared_sram)
#define BL_SHARED_SRAM_SECT LINKER_DT_NODE_REGION_NAME(BL_SHARED_SRAM_NODE)
#define BL_SHARED_SRAM_SIZE DT_REG_SIZE(BL_SHARED_SRAM_NODE)

uint8_t shared_data[BL_SHARED_SRAM_SIZE] Z_GENERIC_SECTION(BL_SHARED_SRAM_SECT);

int shared_data_read(const void *ctx, uint32_t off, void *data, size_t len)
{
	if ((len > BL_SHARED_SRAM_SIZE) || (off > (BL_SHARED_SRAM_SIZE - len))) {
		return -EINVAL;
	}

	(void)memcpy(data, &shared_data[off], len);
	return 0;
}

int shared_data_prog(const void *ctx, uint32_t off, const void *data, size_t len)
{
	if ((len > BL_SHARED_SRAM_SIZE) || (off > (BL_SHARED_SRAM_SIZE - len))) {
		return -EINVAL;
	}

	(void)memcpy(&shared_data[off], data, len);
	return 0;
}

int shared_data_ioctl(const void *ctx, enum sbk_slot_ioctl_cmd cmd, void *data,
		      size_t len)
{
	if (cmd != SBK_SLOT_IOCTL_GET_SIZE) {
		return -ENOTSUP;
	}

	uint32_t *size = (uint32_t *)data;

	*size = BL_SHARED_SRAM_SIZE;
	return 0;
}

int sbk_open_shareddata_slot(struct sbk_slot *slot)
{
	slot->ctx = NULL;
	slot->read = shared_data_read;
	slot->prog = shared_data_prog;
	slot->ioctl = shared_data_ioctl;
	slot->close = NULL;
	return 0;
}

void sbk_watchdog_init(void)
{

}

void sbk_watchdog_feed(void)
{

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
