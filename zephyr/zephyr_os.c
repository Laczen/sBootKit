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

enum slot_type {
	UNKNOWN,
	FLASH_TYPE,
};

struct slot_ctx {
	const void *backend;
	const enum slot_type type;
	size_t size;
};

struct slot_flash_backend {
	const struct device *dev;
	const uint32_t off;
	const size_t block_size;
	const void *data;
};

static int read(const void *ctx, uint32_t off, void *data, size_t len)
{
	const struct slot_ctx *sctx = (const struct slot_ctx *)ctx;
	int rc = -EINVAL;

	if (IS_ENABLED(CONFIG_SBK_IS_FSL) && !IS_ENABLED(CONFIG_FLASH)) {
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

	return rc;
}

static int prog(const void *ctx, uint32_t off, const void *data, size_t len)
{
	const struct slot_ctx *sctx = (const struct slot_ctx *)ctx;
	int rc = -EINVAL;

	if (IS_ENABLED(CONFIG_FLASH) && (sctx->type == FLASH_TYPE)) {
		const struct slot_flash_backend *fb =
			(const struct slot_flash_backend *)sctx->backend;
		const size_t bs = fb->block_size;

		if ((fb->off + off) % bs != 0U) {
			rc = flash_write(fb->dev, fb->off + off, data, len);
			goto end;		 
		}
		
		if (flash_erase(fb->dev, fb->off + off, bs) == 0) {
			rc = flash_write(fb->dev, fb->off + off, data, len);
		}
	}

end:
	return rc;
}

static int address(const void *ctx, uint32_t *address)
{
	const struct slot_ctx *sctx = (const struct slot_ctx *)ctx;
	int rc = -EINVAL;

	if (sctx->type != FLASH_TYPE) {
		goto end;
	}

	const struct slot_flash_backend *fb =
		(const struct slot_flash_backend *)sctx->backend;

	*address += IFLASH_OFFSET + fb->off;
	rc = 0;
end:
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
	slot->address = address;
	slot->close = close;
	slot->cmd = NULL;
}

const struct slot_flash_backend ssl_backend = {
	.off = GET_PARTITION_OFFSET(ssl_partition),
	.block_size = GET_PARTITION_BS(ssl_partition),
	.dev = GET_PARTITION_DEV(ssl_partition),
};

const struct slot_ctx ssl_slot_ctx = {
	.backend = (void *)&ssl_backend,
	.size = GET_PARTITION_SIZE(ssl_partition),
	.type = FLASH_TYPE,
};

int sbk_open_ssl_slot(struct sbk_slot *slot)
{
	open_slot(slot);
	slot->ctx = (void *)&ssl_slot_ctx;
	slot->size = ssl_slot_ctx.size;
	return 0;
}

const struct slot_flash_backend image_backend[] = {
	{
		.off = GET_PARTITION_OFFSET(image0_partition),
		.block_size = GET_PARTITION_BS(image0_partition),
		.dev = GET_PARTITION_DEV(image0_partition),
	},
};

const struct slot_ctx image_slot_ctx[] = {
	{
		.backend = (void *)&image_backend[0],
		.size = GET_PARTITION_SIZE(image0_partition),
		.type = FLASH_TYPE,
	},
};

int sbk_open_image_slot(struct sbk_slot *slot, uint32_t idx)
{
	if (idx >= (sizeof(image_slot_ctx)/sizeof(image_slot_ctx[0]))) {
		return -EINVAL;
	}

	open_slot(slot);
	slot->ctx = (void *)&image_slot_ctx[idx];
	slot->size = image_slot_ctx[idx].size;
	return 0;
}

int sbk_open_rimage_slot(struct sbk_slot *slot, uint32_t idx)
{
	int rc = sbk_open_image_slot(slot, idx);
	slot->prog = NULL;
	return rc;
}

const struct slot_flash_backend update_backend[] = {
	{
		.off = GET_PARTITION_OFFSET(update0_partition),
		.block_size = GET_PARTITION_BS(update0_partition),
		.dev = GET_PARTITION_DEV(update0_partition),
	},
};

const struct slot_ctx update_slot_ctx[] = {
	{
		.backend = (void *)&update_backend[0],
		.size = GET_PARTITION_SIZE(update0_partition),
		.type = FLASH_TYPE,
	},
};

int sbk_open_update_slot(struct sbk_slot *slot, uint32_t idx)
{
	if (idx >= (sizeof(update_slot_ctx)/sizeof(update_slot_ctx[0]))) {
		return -EINVAL;
	}

	open_slot(slot);
	slot->ctx = (void *)&update_slot_ctx[idx];
	slot->size = update_slot_ctx[idx].size;
	return 0;
}

struct flash_backup_data {
	size_t backup_block_size;
};

const struct flash_backup_data backup_data[] = {
	{
		.backup_block_size = GET_PARTITION_OFFSET(update0_partition) -
				     GET_PARTITION_OFFSET(backup0_partition),
	},
};

const struct slot_flash_backend backup_backend[] = {
	{
		.off = GET_PARTITION_OFFSET(backup0_partition),
		.block_size = GET_PARTITION_BS(backup0_partition),
		.dev = GET_PARTITION_DEV(backup0_partition),
		.data = (void *)&backup_data[0], 
	}
};

const struct slot_ctx backup_slot_ctx[] = {
	{
		.backend = (void *)&backup_backend[0],
		.size = GET_PARTITION_SIZE(backup0_partition),
		.type = FLASH_TYPE,
	},
};

static int cmd_bck(const void *ctx, enum sbk_slot_cmds cmd, void *data,
		   size_t len)
{
	if (cmd != SBK_SLOT_CMD_GET_BACKUP_BLOCK_SIZE) {
		return -EINVAL;
	}

	const struct slot_ctx *sctx = (const struct slot_ctx *)ctx;
	int rc = -ENOTSUP;

	if ((len != sizeof(uint32_t)) || (data == NULL)) {
		rc = -EINVAL;
		goto end;
	}

	if (sctx->type != FLASH_TYPE) {
		goto end;
	}

	const struct slot_flash_backend *fb =
		(const struct slot_flash_backend *)sctx->backend;

	if (fb->data == NULL) {
		goto end;
	}

	const struct flash_backup_data *fb_data =
		(const struct flash_backup_data *)fb->data;
	size_t *backup_block_size = (size_t *)data;

	*backup_block_size = fb_data->backup_block_size;
	rc = 0;

end:
	return rc;
}

int sbk_open_backup_slot(struct sbk_slot *slot, uint32_t idx)
{
	if (idx >= (sizeof(backup_slot_ctx)/sizeof(backup_slot_ctx[0]))) {
		return -EINVAL;
	}

	open_slot(slot);
	slot->cmd = cmd_bck;
	slot->ctx = (void *)&backup_slot_ctx[idx];
	slot->size = backup_slot_ctx[idx].size;
	return 0;
}

const struct slot_flash_backend productdata_backend = {
	.off = GET_PARTITION_OFFSET(productdata_partition),
	.block_size = 0,
	.dev = GET_PARTITION_DEV(productdata_partition),
};

const struct slot_ctx productdata_slot_ctx = {
	.backend = (void *)&productdata_backend,
	.size = GET_PARTITION_SIZE(productdata_partition),
	.type = FLASH_TYPE,
};

int sbk_open_productdata_slot(struct sbk_slot *slot)
{
	open_slot(slot);
	slot->prog = NULL;
	slot->ctx = (void *)&productdata_slot_ctx;
	slot->size = productdata_slot_ctx.size;
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

int sbk_open_shareddata_slot(struct sbk_slot *slot)
{
	slot->ctx = NULL;
	slot->read = shared_data_read;
	slot->prog = shared_data_prog;
	slot->size = BL_SHARED_SRAM_SIZE;
	slot->address = NULL;
	slot->cmd = NULL;
	slot->close = NULL;
	return 0;
}

void sbk_watchdog_init(void)
{

}

void sbk_watchdog_feed(void)
{

}

int64_t sbk_uptime_get(void)
{
	return k_uptime_get();
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

	sbk_shell_prompt(sh);
	return 0;
}
