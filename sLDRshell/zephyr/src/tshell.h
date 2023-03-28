/*
 * tinyshell implementation
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TSHELL_H_
#define TSHELL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

struct tshell;

struct tshell_command {
	const char *sname; /* name of the shell it belongs to */
        const char *cmd;
        int (*handler)(const struct tshell *tsh, int argc, char *argv[]);
        const char *help;
};

#define TSHELL_REGISTER_CMD(_sname, _cmd, _handler, _help) 		       \
	STRUCT_SECTION_ITERABLE(tshell_command, 			       \
				tshell ## _ ## _sname ## _ ## _cmd) = {        \
		.sname = STRINGIFY(_sname),				       \
		.cmd = STRINGIFY(_cmd),					       \
                .handler = _handler,					       \
                .help = _help, 				       		       \
        }

int tshell_help_handler(const struct tshell *tsh, int argc, char *argv[]);

struct tshell_data {
	char *cmdbuf;
	size_t cmdbufpos;
	const size_t cmdbufsize;
	void (*bypass)(const struct tshell *tsh, const char *data, size_t len);
};

struct tshell {
	char *name;
	struct tshell_data *tsh_data;
	void (*send_cb)(const void *send_cb_ctx, char c);
	void *send_cb_ctx;
};

#define TSHELL_DECLARE(_name, _bufsize)					       \
	static char _name ## _tshell_cmdbuf[_bufsize];		       	       \
	static struct tshell_data _name ## _tshell_data = {		       \
		.cmdbuf = _name ## _tshell_cmdbuf,			       \
		.cmdbufsize = _bufsize,					       \
	};								       \
	static struct tshell _name = {				       	       \
		.name = STRINGIFY(_name) ,				       \
		.tsh_data = & _name ## _tshell_data,			       \
	};								       \
	TSHELL_REGISTER_CMD(_name, help, tshell_help_handler, "List all commands")

void tshell_register_send_cb(struct tshell *tsh,
			     void (*send_cb)(const void *send_cb_ctx, char c),
			     void *send_cb_ctx);

void tshell_receive(const void *ctx, const char *data, size_t len);
   
void tshell_start(const struct tshell *tsh);

void tshell_set_bypass(const struct tshell *tsh,
		       void (*bypass)(const struct tshell *tsh,
		       		      const char *data, size_t len));

void tshell_put(const struct tshell *tsh, const char *str);

#ifdef __cplusplus
}
#endif

#endif /* TSHELL_H_*/