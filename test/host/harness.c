/* Host test harness for littlessh: a toy device-config shell.
 * SPDX-License-Identifier: MIT */
#include "littlessh.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static uint8_t hostkey[32];

static bool pw_auth(void *u, const char *user, const char *pass){
    (void)u;
    return strcmp(user, "admin") == 0 && strcmp(pass, "hunter2") == 0;
}

/* accept any ECDSA key for user "keyuser" (test only!) */
static bool pk_auth(void *u, const char *user, const uint8_t *blob, size_t n){
    (void)u; (void)blob; (void)n;
    return strcmp(user, "keyuser") == 0;
}

static void on_open(void *u, lssh_session_t *s, const char *exec_cmd){
    (void)u;
    if (exec_cmd){
        lssh_printf(s, "exec:%s\n", exec_cmd);
        lssh_exit(s, 0);
        return;
    }
    lssh_printf(s, "littlessh test shell — user=%s pty=%d\r\n> ",
                lssh_username(s), lssh_has_pty(s) ? 1 : 0);
}

static char line[256];
static size_t line_len;

static void on_data(void *u, lssh_session_t *s, const uint8_t *d, size_t n){
    (void)u;
    for (size_t i = 0; i < n; i++){
        char c = (char)d[i];
        if (c == '\r' || c == '\n'){
            lssh_write(s, "\r\n", 2);
            line[line_len] = 0;
            if (strcmp(line, "exit") == 0){
                lssh_printf(s, "bye\r\n");
                lssh_exit(s, 0);
            } else if (line_len){
                lssh_printf(s, "echo:%s\r\n> ", line);
            } else {
                lssh_write(s, "> ", 2);
            }
            line_len = 0;
        } else if (c == 0x7f || c == 0x08){
            if (line_len){ line_len--; lssh_write(s, "\b \b", 3); }
        } else if (line_len < sizeof(line)-1){
            line[line_len++] = c;
            lssh_write(s, &c, 1);   /* local echo */
        }
    }
}

static void on_pty(void *u, lssh_session_t *s, uint16_t cols, uint16_t rows){
    (void)u; (void)s;
    fprintf(stderr, "harness: pty %ux%u\n", cols, rows);
}

static void on_close(void *u, lssh_session_t *s){
    (void)u; (void)s;
    fprintf(stderr, "harness: session closed\n");
    line_len = 0;
}

int main(int argc, char **argv){
    uint16_t port = argc > 1 ? (uint16_t)atoi(argv[1]) : 2222;

    if (lssh_hostkey_generate(hostkey)){
        fprintf(stderr, "hostkey gen failed\n"); return 1;
    }
    char fp[64];
    if (lssh_hostkey_fingerprint(hostkey, fp, sizeof fp) == 0)
        fprintf(stderr, "harness: host key %s\n", fp);

    lssh_config_t cfg = {
        .port = port,
        .listen_fd = -1,
        .host_key = hostkey,
        .banner = "littlessh harness — authorized use only\n",
        .password_auth = pw_auth,
        .pubkey_auth = pk_auth,
        .on_open = on_open,
        .on_data = on_data,
        .on_pty = on_pty,
        .on_close = on_close,
    };
    return lssh_server_run(&cfg);
}
