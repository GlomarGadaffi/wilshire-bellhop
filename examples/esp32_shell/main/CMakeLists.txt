idf_component_register(SRCS "main.c"
                       PRIV_REQUIRES littlessh nvs_flash esp_eth esp_netif
                                     esp_event esp_driver_spi esp_driver_gpio
                                     esp_hw_support)
