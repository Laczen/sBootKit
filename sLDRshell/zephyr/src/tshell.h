/*
 * TinyShell (tshell)
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
	const char *sname;	/* name of the shell it belongs to */
        const char *cmd;  	/* command string */
        int (*handler)(const struct tshell *tsh, int argc, char *argv[]);
        const char *help;	/* help string */
};

/**
 * @brief TSHELL_REGISTER_CMD: register a tshell command
 * 
 * @param _sname: shell the command belongs to
 * @param _cmd: the command to register (one word)
 * @param _handler: handler function
 * @param _help: help string
 * 
 * e.g. TSHELL_REGISTER_CMD(tsh, list, list_command, "List Images"), registers
 * a command "list" with tshell tsh, when issued in the shell executes 
 * list_command and returns "List Images" as help string.  
 * 
 */
#define TSHELL_REGISTER_CMD(_sname, _cmd, _handler, _help) 		       \
	const STRUCT_SECTION_ITERABLE(tshell_command, 			       \
				      tshell ## _ ## _sname ## _ ## _cmd) = {  \
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

/**
 * @brief TSHELL_DECLARE creates a tshell variable and registers a help
 *        command for it
 * 
 * @param _name: shell name
 * @param _bufsize: size of the buffer to store commands while they are typed
 * 
 */
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


/**
 * @brief tshell_register_send_cb
 * 
 * Register a routine that needs to be called for sending data to the shell user
 * and also provide a (opaque) context for this routine.
 * 
 * @param tsh: shell instance
 * @param send_cb: callback routine 
 * @param send_cb_ctx: callback routine (opaque) context 
 */
void tshell_register_send_cb(struct tshell *tsh,
			     void (*send_cb)(const void *send_cb_ctx, char c),
			     void *send_cb_ctx);

/**
 * @brief tshell_receive
 * 
 * routine that should be called whenever data for the shell needs to be
 * processed
 * 
 * @param ctx: opaque context (this is casted to a (struct shell *))
 * @param data: data that needs processing
 * @param len:  data length
 */
void tshell_receive(const void *ctx, const char *data, size_t len);

/**
 * @brief tshell_start
 * 
 * @param tsh: shell instance to start
 */
void tshell_start(const struct tshell *tsh);

/**
 * @brief tshell_set_bypass
 * 
 * The shell processing can be bypassed to a provided routine, when done
 * bypassing the bypass routine needs to be reset to NULL
 * 
 * @param tsh: shell instance
 * @param bypass: bypass routine 
 */
void tshell_set_bypass(const struct tshell *tsh,
		       void (*bypass)(const struct tshell *tsh,
		       		      const char *data, size_t len));

/**
 * @brief tshell_put
 * 
 * Routine to return info to the shell user
 * 
 * @param tsh: shell instance
 * @param str: info to return
 */
void tshell_put(const struct tshell *tsh, const char *str);

#ifdef __cplusplus
}
#endif

#endif /* TSHELL_H_*/