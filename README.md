# littlessh

Minimal, Apache-2.0-licensed SSH 2.0 **server** for ESP-IDF (5.x and 6.x), written
against the **PSA Crypto API** only — no legacy `mbedtls_*` crypto calls, so it
builds unchanged on mbedTLS 2.28 (host testing), 3.x (IDF 5), and 4.x (IDF 6.0+).

Single C file, single header, no dynamic algorithm negotiation bloat. Designed
for embedded "config shell over SSH" use cases where a web UI is unwanted.

## Algorithm suite (fixed)

| Layer     | Algorithm |
|-----------|-----------|
| KEX       | `curve25519-sha256` (+ `kex-strict-s-v00@openssh.com`, Terrapin mitigation) |
| Host key  | `ecdsa-sha2-nistp256` |
| Cipher    | `aes256-gcm@openssh.com` (AEAD — no separate MAC) |
| Auth      | `password` and/or `publickey` (`ecdsa-sha2-nistp256`) |

Interoperates with stock OpenSSH clients (tested against OpenSSH 9.6).

## Model

- One listening socket, **one blocking client at a time**, callback-driven.
- One `session` channel per connection: `pty-req`, `shell`, `exec`,
  `window-change`, `env` handled; exit-status sent on close.
- Client-initiated rekey supported. Window accounting with output
  fragmentation in `lssh_write()`.
- All large buffers live in a heap-allocated session struct — small task
  stacks are fine (≥ 8 KB recommended; example uses 10 KB).

**Not included:** SFTP, port forwarding, compression, multiple concurrent
clients, RSA/ed25519 host keys.

## API sketch

```c
uint8_t hostkey[32];                       // P-256 scalar, persist in NVS
lssh_hostkey_generate(hostkey);            // first boot only
char fp[64];
lssh_hostkey_fingerprint(hostkey, fp, sizeof fp);  // "SHA256:<b64>"

lssh_config_t cfg = {
    .port = 22,
    .host_key = hostkey,
    .banner = "authorized use only\r\n",
    .password_auth = my_pw_check,          // and/or .pubkey_auth
    .on_open = my_open, .on_data = my_data, .on_pty = my_pty,
};
lssh_server_run(&cfg);                     // blocks; set cfg.stop to exit
```

In callbacks: `lssh_write()`, `lssh_printf()` (no LF→CRLF translation — emit
`\r\n` yourself for ptys), `lssh_exit(s, status)`, `lssh_username(s)`,
`lssh_has_pty(s)`.

If `host_key` is NULL an **ephemeral** key is generated each boot (clients
will see host-key-changed warnings) — fine for bring-up, wrong for production.

## Using as an ESP-IDF component

Drop this directory into `components/littlessh/` (or reference via the
component manager manifest). `psa_crypto_init()` is called internally.
See `examples/esp32_shell/` for a complete NVS-persisted-hostkey config shell.
It brings up W5500 SPI Ethernet on the LilyGO T-ETH-ELITE S3 and has been
verified end-to-end: a stock OpenSSH client negotiates curve25519-sha256 /
ecdsa-sha2-nistp256 / aes256-gcm@openssh.com, authenticates, and runs the
shell. (Note: set `cfg.listen_fd = -1` to have littlessh create the socket —
`0` is a valid fd, so a zero-initialized config would otherwise try fd 0.)

IDF 6.0+ defaults enable the required PSA algorithms (X25519, ECDSA-P256,
AES-GCM, SHA-256). On IDF 5.x verify `MBEDTLS_ECP_DP_CURVE25519_ENABLED` is
set in your sdkconfig.

## Host-side testing

```sh
cd test/host
make            # builds harness with ASan/UBSan (needs libmbedtls-dev)
./run_tests.sh  # integration tests against the real OpenSSH client (needs sshpass)
```

Covers: password auth (accept/reject), publickey auth (accept/reject,
full signature verification), exec, interactive pty shell, long lines.

## Tunables

Override before including / via compiler flags:
`LSSH_MAX_PACKET` (default 4096), `LSSH_WINDOW` (default 65536).

## License

Apache-2.0 — see `LICENSE`.
