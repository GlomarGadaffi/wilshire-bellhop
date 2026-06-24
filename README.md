# glossh

minimal SSH 2.0 server for ESP-IDF on PSA Crypto (curve25519 / aes256-gcm / ecdsa-p256). single-threaded, one client at a time, callback-driven. intended for device configuration consoles, not bulk transfer — no SFTP, no port forwarding, no agent forwarding.

fixed algorithm suite (modern, single path):
- **KEX**: curve25519-sha256 (+ kex-strict-s-v00@openssh.com)
- **Host key**: ecdsa-sha2-nistp256
- **Cipher**: aes256-gcm@openssh.com (AEAD; no separate MAC)
- **Auth**: password and/or publickey (ecdsa-sha2-nistp256)

## integration

```c
#include "littlessh.h"

lssh_config cfg = {
    .port = 22,
    .host_key = my_p256_private_scalar,  /* 32 bytes, big-endian */
    .auth_max_tries = 5,
    .on_auth = my_auth_callback,
    .on_channel_data = my_data_handler,
};

lssh_session_t *sess = lssh_listen(&cfg);
while (sess) {
    sess = lssh_listen(&cfg);  /* blocking, one connection at a time */
}
```

transport parameters:
- max packet: 4 KB (LSSH_MAX_PACKET) — negotiable at compile time
- channel window: 64 KB (LSSH_WINDOW)
- ephemeral host keys if none provided (key change per boot)

## why

bring remote console to microcontrollers without the overhead of OpenSSH or dropbear. justifiable in homelabs, field setups, and scenarios where the alternate (serial console over RF) requires human intervention. based on PSA Crypto for compatibility across ESP-IDF versions (mbedTLS 2.28/3.x/4.x).
