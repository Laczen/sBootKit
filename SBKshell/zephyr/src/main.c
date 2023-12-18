/*
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(sswpshell, LOG_LEVEL_DBG);

#include "sbk/sbk_image.h"
#include "sbk/sbk_slot.h"
#include "sbk/sbk_util.h"
#include "sbk/sbk_product.h"
#include "sbk/sbk_shell.h"

/**
 * @brief sbk_shell interface
 *
 */
int cli_cmd_reboot(const struct sbk_shell *sh, int argc, char *argv[])
{
	sbk_shell_fprintf(sh, "Rebooting\n");
	sbk_reboot();
	return 0;
}

int cli_bypass_test(const struct sbk_shell *sh, const void *data, size_t len)
{
	sbk_shell_fprintf(sh, "bypass called\r\n");
	return 1;
}

int cli_cmd_bypass(const struct sbk_shell *sh, int argc, char *argv[])
{

	if (argc < 2) {
		sbk_shell_fprintf(sh, "Insufficient arguments");
		return 0;
	}

	sbk_shell_fprintf(sh, "Going to bypass mode: ");
	sbk_shell_set_bypass(sh, cli_bypass_test);
	sbk_shell_fprintf(sh, "OK\n");
	return 0;
}

static const struct sbk_shell_cmd shell_commands[] = {
	{"reboot", cli_cmd_reboot, "Reboot the device"},
	{"bypass", cli_cmd_bypass, "Say hello"},
	{"help", sbk_shell_help_handler, "Lists all commands"},
};

SBK_SHELL_DEFINE(tst, shell_commands, 3);

int main(void)
{
	uint32_t data = 0xFF;
	char buf[80];

	LOG_INF("Welcome");
	sbk_shell_init_transport(tst);
	sbk_shell_fprintf(tst, "Welcome %x: %d\r\n", data, data);

	while (true) {
		sbk_shell_receive(tst);
	}

	return 0;
}
