#include <stdint.h>
#include <string.h>
#include "ok_platform.h"

#define FSTORAGE_MISC_DATA_START_ADDR 0x69000
#define FSTORAGE_MISC_DATA_END_ADDR   0x69FFF
#define TEST_TIMES                    50

static void misc_data_evt_handler(nrf_fstorage_evt_t *p_evt)
{
    if (p_evt->result != NRF_SUCCESS) {
        OK_LOG_INFO("--> Event received: ERROR while executing an fstorage operation.");
        return;
    }

    switch (p_evt->id) {
        case NRF_FSTORAGE_EVT_WRITE_RESULT:
            OK_LOG_INFO("--> Write event: %d bytes at address 0x%x.", p_evt->len, p_evt->addr);
            break;
        case NRF_FSTORAGE_EVT_ERASE_RESULT:
            OK_LOG_INFO("--> Erase event: %d page from address 0x%x.", p_evt->len, p_evt->addr);
            break;
        default:
            OK_LOG_INFO("--> Event received: other event");
            break;
    }
}

NRF_FSTORAGE_DEF(nrf_fstorage_t misc_data_fstorage) = {
    .evt_handler = misc_data_evt_handler,
    .start_addr  = FSTORAGE_MISC_DATA_START_ADDR,
    .end_addr    = FSTORAGE_MISC_DATA_END_ADDR,
};

static ok_item_storage_t    dev_config_storage;
static ok_devcfg_keystore_t dev_config;

void xdebug_flash_test(void)
{
    int count = 0;
    OK_LOG_INFO("enter xdebug_flash_test.");

    dev_config_storage.p_fs      = &misc_data_fstorage;
    dev_config_storage.item_data = &dev_config;
    dev_config_storage.item_size  = sizeof(dev_config);
    ok_storage_init(&dev_config_storage);

    memset(&dev_config, 0, sizeof(dev_config));
    dev_config.crc32 = 0x12345678;
    memcpy(dev_config.private_key, "private_key", 12);
    memcpy(dev_config.public_key, "public_key", 11);

    for (int i = 0; i < TEST_TIMES; i++) {
        dev_config.flag_locked = ++count;

        ok_flash_write(&dev_config_storage);
        memset(&dev_config, 0, sizeof(dev_config));
        ok_flash_read(&dev_config_storage);

        if (dev_config.flag_locked == count) {
            OK_LOG_INFO("flash test success %d.", i);
        } else {
            OK_LOG_INFO("flash test failed.");
        }
    }
}
