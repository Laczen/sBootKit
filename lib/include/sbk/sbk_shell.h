/*
 * Shell interface for sbk
 *
 * Inspired by memfault's tinyshell
 * (https://interrupt.memfault.com/blog/firmware-shell)
 *
 * Copyright (c) 2023 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SBK_SHELL_H_
#define SBK_SHELL_H_

#include <stddef.h>

#ifndef CONFIG_SBK_SHELL_CMD_BUFSIZE
#define CONFIG_SBK_SHELL_CMD_BUFSIZE	64
#endif

#ifndef CONFIG_SBK_SHELL_BYPASS_BUFSIZE
#define CONFIG_SBK_SHELL_BYPASS_BUFSIZE	64
#endif

#ifndef CONFIG_SBK_SHELL_PROMPT
#define CONFIG_SBK_SHELL_PROMPT "sbk_shell> "
#endif

#ifndef CONFIG_SBK_SHELL_MAX_ARGS
#define CONFIG_SBK_SHELL_MAX_ARGS	16
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @brief sbk_shell API structures
 * @{
 */

struct sbk_shell;

struct sbk_shell_cmd {
        const char *cmd;
        int (*handler)(const struct sbk_shell *sh, int argc, char *argv[]);
	char *help;
};

struct sbk_shell_data {
	int (*bypass)(const struct sbk_shell *sh, const void *data, size_t len);
	void (*send)(const void *send_ctx, unsigned char c);
	void *send_ctx;
	int (*receive)(const void *receive_ctx, unsigned char *c);
	void *receive_ctx;
	char cmd_buf[CONFIG_SBK_SHELL_CMD_BUFSIZE];
	size_t cmd_buf_pos;
};

struct sbk_shell {
	struct sbk_shell_data *data;
        const struct sbk_shell_cmd *const sbk_shell_cmds;
        const size_t num_sbk_shell_cmds;
};

#define SBK_SHELL_DEFINE(_name, _commands, _num_commands)							\
	struct sbk_shell_data _name ## _sbk_shell_data = {			\
		.bypass = NULL,							\
		.send = NULL,							\
		.send_ctx = NULL,						\
		.receive = NULL,						\
		.receive_ctx = NULL,						\
		.cmd_buf_pos = 0U,						\
	};									\
	const struct sbk_shell _name ## _sbk_shell = {				\
		.data = &_name ## _sbk_shell_data,				\
		.sbk_shell_cmds = _commands,					\
		.num_sbk_shell_cmds = _num_commands,				\
	};									\
	const struct sbk_shell *_name = &_name ## _sbk_shell

void sbk_shell_receive(const struct sbk_shell *sh);

int sbk_shell_print(const struct sbk_shell *sh, const char *str);

void sbk_shell_set_bypass(const struct sbk_shell *sh,
			  int (*bypass)(const struct sbk_shell *sh,
			 		const void *data, size_t len));
int sbk_shell_help_handler(const struct sbk_shell *sh, int argc, char *argv[]);

extern int sbk_shell_init_transport(const struct sbk_shell *sh);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SBK_MOVE_H_ */
