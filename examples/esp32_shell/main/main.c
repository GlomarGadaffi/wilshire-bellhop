/* littlessh ESP32 example: SSH config shell on port 22, over W5500 Ethernet.
 *
 * Board: LilyGO T-ETH-ELITE S3 (ESP32-S3 + W5500). W5500 pin map and init are
 * lifted from the drawbridge project (the device this targets).
 *
 * Connect:  ssh -o StrictHostKeyChecking=no admin@<board-ip>   (password: changeme)
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_eth_mac_w5500.h"
#include "esp_eth_phy_w5500.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "littlessh.h"

static const char *TAG = "ssh_example";

/* ── W5500 SPI pin map: LilyGO T-ETH-ELITE S3 (from drawbridge) ────────── */
#define ETH_SCLK_GPIO 48
#define ETH_MISO_GPIO 47
#define ETH_MOSI_GPIO 21
#define ETH_CS_GPIO   45
#define ETH_INT_GPIO  14
#define ETH_RST_GPIO  -1
#define ETH_SPI_HOST  SPI2_HOST
#define ETH_SPI_MHZ   40

#define GOT_IP_BIT BIT0
static EventGroupHandle_t s_eth_evt;
static esp_ip4_addr_t     s_ip;

static void on_eth_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (id == ETHERNET_EVENT_CONNECTED)         ESP_LOGI(TAG, "eth link up");
    else if (id == ETHERNET_EVENT_DISCONNECTED) ESP_LOGW(TAG, "eth link down");
}

static void on_got_ip(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
    s_ip = e->ip_info.ip;
    ESP_LOGI(TAG, "eth got IP " IPSTR, IP2STR(&s_ip));
    xEventGroupSetBits(s_eth_evt, GOT_IP_BIT);
}

static void eth_start(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    s_eth_evt = xEventGroupCreate();

    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *netif = esp_netif_new(&netif_cfg);
    esp_netif_set_hostname(netif, "glosshlet");

    spi_bus_config_t buscfg = {
        .miso_io_num = ETH_MISO_GPIO, .mosi_io_num = ETH_MOSI_GPIO,
        .sclk_io_num = ETH_SCLK_GPIO, .quadwp_io_num = -1, .quadhd_io_num = -1,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(ETH_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO));

    spi_device_interface_config_t devcfg = {
        .command_bits = 16, .address_bits = 8, .mode = 0,
        .clock_speed_hz = ETH_SPI_MHZ * 1000 * 1000,
        .spics_io_num = ETH_CS_GPIO, .queue_size = 20,
    };

    esp_err_t isr = gpio_install_isr_service(0);   /* W5500 INT needs this on IDF v6 */
    if (isr != ESP_OK && isr != ESP_ERR_INVALID_STATE) ESP_ERROR_CHECK(isr);

    eth_w5500_config_t w5500_cfg = ETH_W5500_DEFAULT_CONFIG(ETH_SPI_HOST, &devcfg);
    w5500_cfg.int_gpio_num = ETH_INT_GPIO;
    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();
    esp_eth_mac_t *mac = esp_eth_mac_new_w5500(&w5500_cfg, &mac_cfg);

    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();
    phy_cfg.autonego_timeout_ms = 0;               /* W5500 has internal PHY */
    phy_cfg.reset_gpio_num = ETH_RST_GPIO;
    esp_eth_phy_t *phy = esp_eth_phy_new_w5500(&phy_cfg);

    esp_eth_config_t eth_cfg = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth = NULL;
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_cfg, &eth));

    uint8_t macaddr[6];
    esp_read_mac(macaddr, ESP_MAC_ETH);
    ESP_ERROR_CHECK(esp_eth_ioctl(eth, ETH_CMD_S_MAC_ADDR, macaddr));

    ESP_ERROR_CHECK(esp_netif_attach(netif, esp_eth_new_netif_glue(eth)));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, on_eth_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, on_got_ip, NULL));
    ESP_ERROR_CHECK(esp_eth_start(eth));

    ESP_LOGI(TAG, "waiting for DHCP lease (W5500, plug in a cable)...");
    xEventGroupWaitBits(s_eth_evt, GOT_IP_BIT, pdFALSE, pdTRUE, pdMS_TO_TICKS(30000));
}

/* ── host key persistence: 32-byte P-256 scalar in NVS ─────────────────── */
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

/* ── auth + session callbacks (header API: user ptr first) ─────────────── */
static bool auth_password(void *ud, const char *user, const char *pass)
{
    (void)ud;
    return strcmp(user, "admin") == 0 && strcmp(pass, "changeme") == 0;
}

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

    ESP_LOGI(TAG, "SSH ready: ssh -o StrictHostKeyChecking=no admin@" IPSTR
             "  (password: changeme)", IP2STR(&s_ip));

    lssh_config_t cfg = {
        .port = 22,               /* listen_fd left 0 -> littlessh creates the socket */
        .host_key = hostkey,
        .auth_max_tries = 3,
        .recv_timeout_ms = 300000,
        .banner = "pocket-dial — authorized use only\r\n",
        .password_auth = auth_password,
        .on_open = on_open,
        .on_data = on_data,
    };
    lssh_server_run(&cfg);   /* blocks; serves one client at a time */
    vTaskDelete(NULL);
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    eth_start();
    xTaskCreate(ssh_task, "littlessh", 10240, NULL, 5, NULL);
}
