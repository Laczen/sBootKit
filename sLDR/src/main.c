/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#include "sbk/sbk_slot.h"
#include "sbk/sbk_util.h"
#include "sbk/sbk_product.h"
#include "sbk/sbk_image.h"
#include "sbk/sbk_log.h"
#include "sbk/sbk_shell.h"

#ifndef CONFIG_PNAME
#define CONFIG_PNAME "TEST"
#endif
#ifndef CONFIG_PVER_MAJ
#define CONFIG_PVER_MAJ 0
#endif
#ifndef CONFIG_PVER_MIN
#define CONFIG_PVER_MIN 0
#endif
#ifndef CONFIG_PVER_REV
#define CONFIG_PVER_REV 0
#endif

static struct sbk_version product_version = {
	.major = CONFIG_PVER_MAJ,
	.minor = CONFIG_PVER_MIN,
	.revision = CONFIG_PVER_REV,
};

static struct sbk_product product = {
	.name = CONFIG_PNAME,
	.name_size = sizeof(CONFIG_PNAME) - 1,
	.version = &product_version,
};

#define BOOT_RETRIES 4

/**
 * @brief sbk_shell interface
 *
 */
int cli_cmd_reboot(const struct sbk_shell *sh, int argc, char *argv[])
{
	sbk_shell_print(sh, "Rebooting\n");
	sbk_reboot();
	return 0;
}

int cli_cmd_info(const struct sbk_shell *sh, int argc, char *argv[])
{
	size_t sltcnt;
	struct sbk_slot slot;
	struct sbk_image_state state;
	char buf[80];

	sltcnt = 0U;
	(void)snprintf(buf, sizeof(buf), "Image slots:\n");
	sbk_shell_print(sh, buf);
	while (sbk_open_image_slot(&slot, sltcnt) == 0) {
		sltcnt++;
		(void)sbk_slot_close(&slot);
	}

	while (sltcnt != 0) {
		sltcnt--;
		if (sbk_open_image_slot(&slot, sltcnt) != 0) {
			continue;
		}
		sbk_image_sldr_state(&slot, &state);
		(void)sbk_slot_close(&slot);
		(void)snprintf(buf, sizeof(buf), "slt %d: state %x\n", sltcnt,
			       state.state);
		sbk_shell_print(sh, buf);
	}

	sltcnt = 0U;
	(void)snprintf(buf, sizeof(buf), "Update slots:\n");
	sbk_shell_print(sh, buf);
	while (sbk_open_update_slot(&slot, sltcnt) == 0) {
		sltcnt++;
		(void)sbk_slot_close(&slot);
	}

	while (sltcnt != 0) {
		sltcnt--;
		if (sbk_open_update_slot(&slot, sltcnt) != 0) {
			continue;
		}
		sbk_image_sldr_state(&slot, &state);
		(void)sbk_slot_close(&slot);
		(void)snprintf(buf, sizeof(buf), "slt %d: state %x\n", sltcnt,
			       state.state);
		sbk_shell_print(sh, buf);
	}

	sltcnt = 0U;
	(void)snprintf(buf, sizeof(buf), "Backup slots:\n");
	sbk_shell_print(sh, buf);
	while (sbk_open_backup_slot(&slot, sltcnt) == 0) {
		sltcnt++;
		(void)sbk_slot_close(&slot);
	}

	while (sltcnt != 0) {
		sltcnt--;
		if (sbk_open_backup_slot(&slot, sltcnt) != 0) {
			continue;
		}
		sbk_image_sldr_state(&slot, &state);
		(void)sbk_slot_close(&slot);
		(void)snprintf(buf, sizeof(buf), "slt %d: state %x\n", sltcnt,
			       state.state);
		sbk_shell_print(sh, buf);
	}

	return 0;
}

int cli_bypass_test(const struct sbk_shell *sh, const void *data, size_t len)
{
	sbk_shell_print(sh, "bypass called\r\n");
	return 1;
}

int cli_cmd_bypass(const struct sbk_shell *sh, int argc, char *argv[])
{

	if (argc < 2) {
		sbk_shell_print(sh, "Insufficient arguments");
		return 0;
	}

	sbk_shell_print(sh, "Going to bypass mode: ");
	sbk_shell_set_bypass(sh, cli_bypass_test);
	sbk_shell_print(sh, "OK\n");
	return 0;
}

static const struct sbk_shell_cmd shell_commands[] = {
	{"reboot", cli_cmd_reboot, "Reboot the device"},
	{"info", cli_cmd_info, "Get image info"},
	{"bypass", cli_cmd_bypass, "Say hello"},
	{"help", sbk_shell_help_handler, "Lists all commands"},
};

SBK_SHELL_DEFINE(tst, shell_commands, 4);

bool swap_images(void)
{
	struct sbk_slot slot;
	uint32_t sltcnt = 0;
	bool rv;

	while (sbk_open_image_slot(&slot, sltcnt) == 0) {
		sltcnt++;
		(void)sbk_slot_close(&slot);
	}

	while ((sltcnt != 0) && (!rv)) {
		sltcnt--;
		if (sbk_image_sfsl_swap(sltcnt)) {
			rv = true;
		}
	}

	return rv;
}

int main(void)
{
	sbk_set_product(&product);

	if (swap_images()) {
		sbk_reboot();
	}

	sbk_shell_init_transport(tst);
	sbk_shell_print(tst, "Welcome");

	while (true) {
		sbk_shell_receive(tst);
	}
}
