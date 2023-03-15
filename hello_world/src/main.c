/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>

#define PARTITION_OFFSET	FIXED_PARTITION_OFFSET(storage_partition)
#define PARTITION_DEVICE	FIXED_PARTITION_DEVICE(storage_partition)

void main(void)
{
	const struct device *flash_dev = PARTITION_DEVICE;
	uint8_t buf[16];
	int rc;

	printk("Hello World! %s\n", CONFIG_BOARD);
	rc = flash_read(flash_dev, 0, buf, sizeof(buf));
	printk("FR %d\n", rc);
}
