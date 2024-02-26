/*
 * Copyright (c) 2023 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "sbk/sbk_shell.h"

#define SBK_SHELL_FOREACH_CMD(cmd, shell_cmds, num_shell_cmds)                  \
	for (const struct sbk_shell_cmd *cmd = shell_cmds;                      \
	     cmd < &shell_cmds[num_shell_cmds]; ++cmd)

static const struct sbk_shell_cmd *sbk_shell_get_cmd(const struct sbk_shell *sh,
						     const char *name)
{
	SBK_SHELL_FOREACH_CMD(cmd, sh->sbk_shell_cmds, sh->num_sbk_shell_cmds)
	{
		if (strcmp(cmd->cmd, name) == 0) {
			return cmd;
		}
	}

	return NULL;
}

static void sbk_shell_print(const struct sbk_shell *sh, const char *str)
{
	struct sbk_shell_data *sh_data = sh->data;

	if (sh_data->send == NULL) {
		return;
	}

	while (*str != '\0') {
		sh_data->send(sh_data->send_ctx, (*str++));
	}
}

void sbk_shell_fprintf(const struct sbk_shell *sh, const char *fmt, ...)
{
	char buf[80];
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	sbk_shell_print(sh, buf);
}

static void sbk_shell_echo(const struct sbk_shell *sh, char c)
{
	if (c == '\n') {
		sbk_shell_print(sh, "\r\n");
		return;
	}

	if (c == '\b') {
		sbk_shell_print(sh, "\b \b");
		return;
	}

	char str[2] = {c, '\0'};
	sbk_shell_print(sh, str);
}

static bool sbk_shell_cmd_buffer_full(const struct sbk_shell *sh)
{
	return sh->data->cmd_buf_pos >= CONFIG_SBK_SHELL_CMD_BUFSIZE;
}

static void sbk_shell_reset_cmd_buffer(const struct sbk_shell *sh)
{
	memset(sh->data->cmd_buf, 0, CONFIG_SBK_SHELL_CMD_BUFSIZE);
	sh->data->cmd_buf_pos = 0U;
}

static void sbk_shell_process(const struct sbk_shell *sh)
{
	char *argv[CONFIG_SBK_SHELL_MAX_ARGS] = {0};
	int argc = 0;

	char *next_arg = NULL;
	for (size_t i = 0;
	     ((i < sh->data->cmd_buf_pos) && (argc < CONFIG_SBK_SHELL_MAX_ARGS));
	     ++i) {
		char *const c = &sh->data->cmd_buf[i];

		if ((*c == ' ') || (i == sh->data->cmd_buf_pos - 1)) {
			*c = '\0';
			if (next_arg) {
				argv[argc++] = next_arg;
				next_arg = NULL;
			}
		} else if (!next_arg) {
			next_arg = c;
		}
	}

	while (argc >= 1) {
		const struct sbk_shell_cmd *cmd = sbk_shell_get_cmd(sh, argv[0]);

		if (cmd != NULL) {
			int rc = cmd->handler(sh, argc, argv);

			if (rc != 0) {
				sbk_shell_print(sh, "command: ");
				sbk_shell_print(sh, argv[0]);
				sbk_shell_print(sh, "returned error\r\n");
			}

			break;
		}

		sbk_shell_print(sh, "Unknown command: ");
		sbk_shell_print(sh, argv[0]);
		sbk_shell_print(sh, "\r\n");
		sbk_shell_print(sh, "Type 'help' to list all commands\r\n");
		break;
	}

	sbk_shell_reset_cmd_buffer(sh);
	sbk_shell_prompt(sh);
}

void sbk_shell_prompt(const struct sbk_shell *sh)
{
	if (sh->data->bypass != NULL) {
		return;
	}

	sbk_shell_print(sh, "\r\n");
	sbk_shell_print(sh, CONFIG_SBK_SHELL_PROMPT);
}

bool sbk_shell_receive(const struct sbk_shell *sh)
{
	struct sbk_shell_data *sh_data = sh->data;
	size_t cnt = 0;
	
	if (sh_data->receive == NULL) {
		return false;
	}

	if (sh_data->bypass != NULL) {
		unsigned char buf[CONFIG_SBK_SHELL_BYPASS_BUFSIZE];
		
		while (sh_data->receive(sh_data->receive_ctx, &buf[cnt]) == 0) {
			cnt++;
		}

		if (cnt == 0U) {
			return false;
		}

		if (sh_data->bypass(sh, buf, cnt) != 0) {
			sbk_shell_set_bypass(sh, NULL);
		}

		return true;
	}

	char c;

	while (sh_data->receive(sh_data->receive_ctx, &c) == 0) {
		cnt++;
		if (c == '\n') {
			continue;
		}

		sbk_shell_echo(sh, c);

		if (c == '\b') {
			if (sh->data->cmd_buf_pos == 0) {
				continue;
			}

			sh->data->cmd_buf_pos--;
			sh->data->cmd_buf[sh->data->cmd_buf_pos] = 0;
			continue;
		}

		sh->data->cmd_buf[sh->data->cmd_buf_pos++] = c;

		if ((c == '\r') || (sbk_shell_cmd_buffer_full(sh))) {
			sbk_shell_process(sh);
			continue;
		}
	}

	return (cnt == 0U) ? false : true;
}

void sbk_shell_set_bypass(const struct sbk_shell *sh,
			  int (*bypass)(const struct sbk_shell *sh,
					const void *data, size_t len))
{
	struct sbk_shell_data *sh_data = sh->data;

	sh_data->bypass = bypass;

	if (bypass == NULL) {
		sbk_shell_prompt(sh);
	}
}

int sbk_shell_help_handler(const struct sbk_shell *sh, int argc, char *argv[])
{
	SBK_SHELL_FOREACH_CMD(cmd, sh->sbk_shell_cmds, sh->num_sbk_shell_cmds)
	{
		sbk_shell_print(sh, "\r\n");
		sbk_shell_print(sh, cmd->cmd);
		sbk_shell_print(sh, ": ");
		sbk_shell_print(sh, cmd->help);
	}

	return 0;
}
