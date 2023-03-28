#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <zephyr/kernel.h>
#include "tshell.h"

#define TSHELL_MAX_ARGS (16)
#define TSHELL_PROMPT "tshell> "

void tshell_register_send_cb(struct tshell *tsh,
			     void (*send_cb)(const void *send_cb_ctx, char c),
			     void *send_cb_ctx)
{
	tsh->send_cb = send_cb;
	tsh->send_cb_ctx = send_cb_ctx;
}

static void tshell_send(const struct tshell *tsh, char c)
{
        if (tsh->send_cb == NULL) {
                return;
        }
        return tsh->send_cb(tsh->send_cb_ctx, c);
}

static void tshell_echo(const struct tshell *tsh, char c)
{
        if (c == '\n' || c == '\r') {
                tshell_send(tsh, '\r');
                tshell_send(tsh, '\n');
        }  else {
                tshell_send(tsh, c);
        }
}

static void tshell_echo_str(const struct tshell *tsh, const char *str)
{
        for (const char *c = str; *c != '\0'; ++c) {
                tshell_echo(tsh, *c);
        }
}

static void tshell_send_prompt(const struct tshell *tsh)
{
        tshell_echo_str(tsh, TSHELL_PROMPT);
}

static struct tshell_command *tshell_find_cmd(const struct tshell *tsh,
                                              const char *cmd)
{
        STRUCT_SECTION_FOREACH(tshell_command, h) {
                if ((strcmp(h->sname, tsh->name)==0) && 
                    (strcmp(h->cmd, cmd)== 0)) {
                        return h;
                }
        
        }

        return NULL;
}

static bool tshell_cmdbuf_full(const struct tshell *tsh)
{
  return tsh->tsh_data->cmdbufpos >= tsh->tsh_data->cmdbufsize;
}

static void tshell_cmdbuf_reset(const struct tshell *tsh)
{
        memset(tsh->tsh_data->cmdbuf, 0, tsh->tsh_data->cmdbufsize);
        tsh->tsh_data->cmdbufpos = 0U;
}

static void tshell_process(const struct tshell *tsh)
{
        char *argv[TSHELL_MAX_ARGS] = {0};
        int argc = 0;
        char *next_arg = NULL;

        for (size_t i = 0; i < tsh->tsh_data->cmdbufpos; ++i) {
                char *const c = &tsh->tsh_data->cmdbuf[i];

                if ((*c == ' ') || (i == (tsh->tsh_data->cmdbufpos - 1))) {
                        *c = '\0';
                        if (next_arg) {
                                argv[argc++] = next_arg;
                                next_arg = NULL;
                        }
                } else if (!next_arg) {
                        next_arg = c;
                }

                if (argc == TSHELL_MAX_ARGS) {
                        break;
                }
        }

        if (tsh->tsh_data->cmdbufpos == tsh->tsh_data->cmdbufsize) {
                tshell_echo(tsh, '\n');
        }

        if (argc >= 1) {
                const struct tshell_command *command = tshell_find_cmd(tsh, argv[0]);
                if (!command) {
                        tshell_echo_str(tsh, "Unknown command: ");
                        tshell_echo_str(tsh, argv[0]);
                        tshell_echo(tsh, '\n');
                        tshell_echo_str(tsh, "Type 'help' to list commands\n");
                } else {
                        command->handler(tsh, argc, argv);
                }
        }

        tshell_cmdbuf_reset(tsh);
        if (tsh->tsh_data->bypass == NULL) {
                tshell_send_prompt(tsh);
        }
}


void tshell_receive(const void *ctx, const char *data, size_t len)
{
        const struct tshell *tsh = (const struct tshell *)ctx;
        
        if (tsh->tsh_data->bypass != NULL) {
                tsh->tsh_data->bypass(tsh, data, len);
                return;
        }

        char *cdata = (char *)data;
        
        while (len != 0U) {
                char c = (*cdata);

                cdata++;
                len--;

                /* ignore empty lines */
                if (((c == '\n') || (c == '\r') || (c == '\b')) &&
                     (tsh->tsh_data->cmdbufpos == 0U))  {
                        continue;
                }

                tshell_echo(tsh, c);
                
                if (c == '\b') {
                        tsh->tsh_data->cmdbufpos--;
                        tshell_echo(tsh, ' ');
                        tshell_echo(tsh, '\b');
                } else {
                        tsh->tsh_data->cmdbuf[tsh->tsh_data->cmdbufpos++] = c;
                }
                
                if ((c == '\r') || (c == '\n') || tshell_cmdbuf_full(tsh)) {
                        tshell_process(tsh);
                }
        }

}

void tshell_start(const struct tshell *tsh)
{
        tshell_cmdbuf_reset(tsh);
        tshell_echo_str(tsh, "\n" TSHELL_PROMPT);
}

void tshell_set_bypass(const struct tshell *tsh, 
                       void (*bypass)(const struct tshell *tsh, const char *c,
                                      size_t len))
{
        tsh->tsh_data->bypass = bypass;
        if (tsh->tsh_data->bypass == NULL) {
                tshell_echo_str(tsh, "\n" TSHELL_PROMPT);
        }
}

void tshell_put(const struct tshell *tsh, const char *str) {
        tshell_echo_str(tsh, str);
        tshell_echo(tsh, '\n');
}

int tshell_help_handler(const struct tshell *tsh, int argc, char *argv[]) {
        STRUCT_SECTION_FOREACH(tshell_command, h) {
                if (strcmp(h->sname, tsh->name) == 0) {
                        tshell_echo_str(tsh, h->cmd);
                        tshell_echo_str(tsh, ": ");
                        tshell_echo_str(tsh, h->help);
                        tshell_echo(tsh, '\n');
                }
        
        }

        return 0;
}