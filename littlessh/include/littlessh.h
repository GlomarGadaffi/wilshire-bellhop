/*
 * littlessh — a minimal SSH 2.0 server for ESP-IDF (and POSIX), built on
 * the PSA Crypto API (mbedTLS 2.28 / 3.x / 4.x — i.e. ESP-IDF 5.x and 6.x).
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Algorithms (fixed, modern, single suite):
 *   KEX:       curve25519-sha256  (+ kex-strict-s-v00@openssh.com)
 *   Host key:  ecdsa-sha2-nistp256
 *   Cipher:    aes256-gcm@openssh.com (AEAD; no separate MAC)
 *   Auth:      password and/or publickey (ecdsa-sha2-nistp256)
 *
 * Model: one listener, one client at a time, blocking, callback-driven.
 * Intended for device configuration consoles, not bulk transfer. No SFTP,
 * no port forwarding, no agent forwarding, one "session" channel.
 */

#ifndef LITTLESSH_H
#define LITTLESSH_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LSSH_VERSION_STR "0.1.0"

/* Transport-level maximum packet size we accept/emit. OpenSSH KEXINIT is
 * ~1.5 KB; 4 KB leaves headroom. Raise if you need bigger channel writes
 * in a single packet (lssh_write fragments regardless). */
#ifndef LSSH_MAX_PACKET
#define LSSH_MAX_PACKET 4096
#endif

/* Our advertised channel window. */
#ifndef LSSH_WINDOW
#define LSSH_WINDOW 65536
#endif

typedef struct lssh_session lssh_session_t;

typedef struct lssh_config {
    /* --- listener --- */
    uint16_t port;        /* TCP port; 0 => 22 */
    int listen_fd;        /* >=0: use an already-bound, listening fd; -1: create one */

    /* --- identity --- */
    const uint8_t *host_key;  /* 32-byte P-256 private scalar (big-endian).
                               * NULL => ephemeral key per boot (clients will
                               * see the host key change; fine for bring-up,
                               * wrong for production). */

    /* --- policy --- */
    uint32_t auth_max_tries;   /* 0 => 5 */
    uint32_t recv_timeout_ms;  /* 0 => no socket receive timeout */
    const char *banner;        /* optional pre-auth banner text (may be NULL) */

    /* --- authentication callbacks (at least one must be non-NULL) --- */
    /* Return true to accept. `username`/`password` are NUL-terminated. */
    bool (*password_auth)(void *user, const char *username, const char *password);
    /* `blob` is the raw SSH wire public-key blob (algorithm-tagged), exactly
     * the base64-decoded middle field of an authorized_keys line. Compare it
     * byte-for-byte against stored authorized keys. littlessh verifies the
     * signature; you only decide whether the key is authorized. */
    bool (*pubkey_auth)(void *user, const char *username,
                        const uint8_t *blob, size_t blob_len);

    /* --- session callbacks --- */
    /* Channel is up and the client requested a shell (exec_cmd == NULL) or
     * command execution (exec_cmd != NULL, NUL-terminated). Safe to call
     * lssh_write()/lssh_exit() from here. */
    void (*on_open)(void *user, lssh_session_t *s, const char *exec_cmd);
    /* Keystrokes / stdin from the client. */
    void (*on_data)(void *user, lssh_session_t *s, const uint8_t *data, size_t len);
    /* pty-req and window-change. May be NULL. */
    void (*on_pty)(void *user, lssh_session_t *s, uint16_t cols, uint16_t rows);
    /* Channel torn down (client close, EOF+close, or transport loss). */
    void (*on_close)(void *user, lssh_session_t *s);

    void *user;                /* opaque pointer handed to every callback */
    volatile bool *stop;       /* optional: set *stop=true to make
                                * lssh_server_run() return after the current
                                * connection ends */
} lssh_config_t;

/* Blocking accept loop. Serves one client at a time. Returns 0 on a clean
 * stop (via cfg->stop), negative on unrecoverable setup error. Run it in a
 * dedicated FreeRTOS task on ESP-IDF (>= 8 KB stack recommended). */
int lssh_server_run(const lssh_config_t *cfg);

/* Write to the client's terminal (channel stdout). Fragments to the peer's
 * window/packet limits; may internally pump the connection while waiting
 * for window space. Returns bytes written or -1 if the channel is gone. */
ssize_t lssh_write(lssh_session_t *s, const void *data, size_t len);

/* printf convenience over lssh_write (LF is not translated; send \r\n
 * yourself when a pty was requested). */
ssize_t lssh_printf(lssh_session_t *s, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Send exit-status, EOF and close the channel. The transport then winds
 * down and lssh_server_run() loops back to accept(). */
int lssh_exit(lssh_session_t *s, uint32_t exit_status);

/* Authenticated username of this session ("" before auth). */
const char *lssh_username(const lssh_session_t *s);

/* Whether the client requested a pty. */
bool lssh_has_pty(const lssh_session_t *s);

/* --- host key helpers --- */
/* Generate a fresh P-256 host key scalar (store it: NVS on ESP-IDF). */
int lssh_hostkey_generate(uint8_t out[32]);
/* OpenSSH-style fingerprint "SHA256:<base64>" of the corresponding public
 * key, for display/TOFU. Returns 0 on success. */
int lssh_hostkey_fingerprint(const uint8_t key[32], char *out, size_t outlen);

#ifdef __cplusplus
}
#endif
#endif /* LITTLESSH_H */
