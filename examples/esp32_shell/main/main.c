/* littlessh ESP32 example: SSH config shell on port 22.
 * Assumes Wi-Fi/netif already up (use protocol_examples_common or your own init).
 */
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "littlessh.h"

static const char *TAG = "ssh_example";

/* --- host key persistence: 32-byte P-256 scalar in NVS --- */
static esp_err_t hostkey_load_or_create(uint8_t key[32])
{
    nvs_handle_t h;
    esp_err_t err = nvs_open("littlessh", NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    size_t len = 32;
    err = nvs_get_blob(h, "hostkey", key, &len);
    if (err == ESP_OK && len == 32) { nvs_close(h); return ESP_OK; }
    ESP_LOGW(TAG, "generating new host key");
    if (lssh_hostkey_generate(key) != 0) { nvs_close(h); return ESP_FAIL; }
    err = nvs_set_blob(h, "hostkey", key, 32);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

/* --- auth --- */
static bool auth_password(void *ud, const char *user, const char *pass)
{
    (void)ud;
    return strcmp(user, "admin") == 0 && strcmp(pass, "changeme") == 0;
}

/* --- session callbacks --- */
static void on_open(void *ud, lssh_session_t *s, const char *exec_cmd)
{
    (void)ud;
    if (exec_cmd) { lssh_printf(s, "unsupported: %s\r\n", exec_cmd); lssh_exit(s, 1); return; }
    lssh_printf(s, "pocket-dial config shell. 'help' for commands.\r\n> ");
}

static void on_data(void *ud, lssh_session_t *s, const uint8_t *data, size_t len)
{
    (void)ud;
    static char line[128];
    static size_t pos = 0;
    for (size_t i = 0; i < len; i++) {
        char c = (char)data[i];
        if (c == '\r' || c == '\n') {
            lssh_printf(s, "\r\n");
            line[pos] = 0;
            if (strcmp(line, "exit") == 0) {
                lssh_printf(s, "bye\r\n");
                lssh_exit(s, 0);
                pos = 0;
                return;
            } else if (strcmp(line, "help") == 0) {
                lssh_printf(s, "commands: help, exit\r\n");
            } else if (pos > 0) {
                lssh_printf(s, "unknown: %s\r\n", line);
            }
            pos = 0;
            lssh_printf(s, "> ");
        } else if (c == 0x7f || c == 0x08) {  /* backspace */
            if (pos > 0) { pos--; lssh_printf(s, "\b \b"); }
        } else if (pos < sizeof(line) - 1 && c >= 0x20) {
            line[pos++] = c;
            lssh_write(s, (const uint8_t *)&c, 1);  /* echo */
        }
    }
}

static void ssh_task(void *arg)
{
    (void)arg;
    static uint8_t hostkey[32];
    ESP_ERROR_CHECK(hostkey_load_or_create(hostkey));

    char fp[64];
    if (lssh_hostkey_fingerprint(hostkey, fp, sizeof(fp)) == 0)
        ESP_LOGI(TAG, "host key fingerprint: %s", fp);

    lssh_config_t cfg = {
        .port = 22,
        .host_key = hostkey,
        .auth_max_tries = 3,
        .recv_timeout_ms = 300000,
        .banner = "pocket-dial — authorized use only\r\n",
        .password_auth = auth_password,
        .on_open = on_open,
        .on_data = on_data,
    };
    /* blocks; serves one client at a time forever (stop flag not set) */
    lssh_server_run(&cfg);
    vTaskDelete(NULL);
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    /* ... bring up Wi-Fi / Ethernet here ... */
    xTaskCreate(ssh_task, "littlessh", 10240, NULL, 5, NULL);
}
