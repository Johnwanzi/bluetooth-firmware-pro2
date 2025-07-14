#include <stdint.h>
#include <stdbool.h>
#include "crc32.h"
#include "nrf_uicr.h"
#include "ecdsa.h"
#include "ok_device_config.h"
#include "ok_storage.h"
#include "ok_platform.h"

static void devcfg_evt_handler(nrf_fstorage_evt_t *p_evt);

static ok_devcfg_t dev_config;
static ok_item_storage_t    dev_config_storage;

NRF_FSTORAGE_DEF(nrf_fstorage_t devcfg_data_fstorage) = {
    .evt_handler = devcfg_evt_handler,
    .start_addr  = DEVICE_CONFIG_START_ADDR,
    .end_addr    = DEVICE_CONFIG_END_ADDR,
};

static void devcfg_evt_handler(nrf_fstorage_evt_t *p_evt)
{
    if (p_evt->result != NRF_SUCCESS) {
        OK_LOG_INFO("devcfg fstorage error %d.", p_evt->result);
        return;
    }

    switch (p_evt->id) {
        case NRF_FSTORAGE_EVT_WRITE_RESULT:
            OK_LOG_INFO("devcfg write event: %d bytes at address 0x%x.", p_evt->len, p_evt->addr);
            break;
        case NRF_FSTORAGE_EVT_ERASE_RESULT:
            OK_LOG_INFO("devcfg erase event: %d page from address 0x%x.", p_evt->len, p_evt->addr);
            break;
        default:
            OK_LOG_INFO("devcfg received: other event");
            break;
    }
}

static uint32_t devcfg_keystore_crc32(ok_devcfg_keystore_t* keystore)
{
    uint32_t crc32 = 0;
    crc32 = crc32_compute((uint8_t*)(&(keystore->private_key)), sizeof(keystore->private_key), NULL);
    crc32 = crc32_compute((uint8_t*)(&(keystore->public_key)), sizeof(keystore->public_key), &crc32);

    return crc32;
}

static bool devcfg_keystore_restore_from_uicr(ok_devcfg_keystore_t* keystore)
{
    ok_devcfg_keystore_t keystore_uicr = {0};

    if (!uicr_get_customer(&keystore_uicr, sizeof(keystore_uicr))) {
        return false;
    }

    if (memcmp(&keystore_uicr, keystore, sizeof(keystore_uicr)) == 0) {
        return true;
    }

    bool is_flash_keystore_valid = ok_devcfg_keystore_validate(keystore);
    bool is_uicr_keystore_valid = ok_devcfg_keystore_validate(&keystore_uicr);

    if (!is_uicr_keystore_valid) {
        return false;
    }

    if (!is_flash_keystore_valid) {
        // keystore in flash is not valid
        memcpy(keystore, &keystore_uicr, sizeof(keystore_uicr));
    } else {
        // both valid, using uicr as default
        if (keystore->flag_locked != DEVICE_CONFIG_FLAG_MAGIC) {
            memcpy(keystore, &keystore_uicr, sizeof(keystore_uicr));
        }
    }

    return true;
}

static bool devcfg_keystore_backup_to_uicr(ok_devcfg_keystore_t* keystore)
{
    ok_devcfg_keystore_t keystore_uicr = {0};

    if (!uicr_get_customer(&keystore_uicr, sizeof(keystore_uicr))) {
        return false;
    }

    if (memcmp(&keystore_uicr, keystore, sizeof(keystore_uicr)) == 0) {
        return true;
    }

    bool is_flash_keystore_valid = ok_devcfg_keystore_validate(keystore);
    bool is_uicr_keystore_valid = ok_devcfg_keystore_validate(&keystore_uicr);

    if (!is_flash_keystore_valid) {
        return false;
    }

    if (!is_uicr_keystore_valid) {
        return uicr_update_customer(keystore, sizeof(keystore));
    } else {
        if (keystore_uicr.flag_locked != DEVICE_CONFIG_FLAG_MAGIC) {
            return uicr_update_customer(keystore, sizeof(keystore));
        }
    }

    return false;
}

static bool devcfg_keystore_backup_compare(ok_devcfg_keystore_t* keystore)
{
    ok_devcfg_keystore_t keystore_uicr = {0};

    uicr_get_customer(&keystore_uicr, sizeof(keystore_uicr));

    return (memcmp(&keystore_uicr, keystore, sizeof(keystore_uicr)) == 0);
}

static bool devcfg_keystore_setup_new(ok_devcfg_keystore_t* keystore)
{
    generate_ecdsa_keypair(keystore->private_key, keystore->public_key);

    keystore->crc32 = devcfg_keystore_crc32(keystore);

    return devcfg_keystore_backup_to_uicr(keystore);
}

bool ok_devcfg_keystore_validate(ok_devcfg_keystore_t* keystore)
{
    return (keystore->crc32 == devcfg_keystore_crc32(keystore));
}

bool ok_devcfg_keystore_lock(ok_devcfg_keystore_t* keystore)
{
    if (!ok_devcfg_keystore_validate(keystore)) {
        return false;
    }
        
    // error out if already locked
    if (keystore->flag_locked == DEVICE_CONFIG_FLAG_MAGIC) {
        return false;
    }

    keystore->flag_locked = DEVICE_CONFIG_FLAG_MAGIC;

    return true;
}

void ok_device_config_init(void)
{
    bool commit_pending = false;

    dev_config_storage.init = false;
    dev_config_storage.item_data = &dev_config;
    dev_config_storage.item_size = sizeof(dev_config);
    dev_config_storage.p_fs = &devcfg_data_fstorage;
    ok_storage_init(&dev_config_storage);

    // check header and version
    if (dev_config.header != DEVICE_CONFIG_HEADER_MAGIC || dev_config.version != DEVICE_CONFIG_VERSION) {
        dev_config.header = DEVICE_CONFIG_HEADER_MAGIC;
        dev_config.version = DEVICE_CONFIG_VERSION;
        commit_pending = true;
    }

    // check settings
    if (dev_config.settings.flag_initialized != DEVICE_CONFIG_FLAG_MAGIC) {
        OK_LOG_WARN("Settings not initialized, try to initialize.");
        dev_config.settings.flag_initialized = DEVICE_CONFIG_FLAG_MAGIC;
        dev_config.settings.bt_ctrl = 0;
        commit_pending = true;
    }

    if (!ok_devcfg_keystore_validate(&dev_config.keystore)) {
        OK_LOG_WARN("Keystore invalid, try to recover.");

        do {
            // recover from uicr
            if (devcfg_keystore_restore_from_uicr(&dev_config.keystore)) {
                OK_LOG_INFO("Keystore recovered from uicr.");
                commit_pending = true;
                break;
            }

            //  recover failed and generate new key
            if (devcfg_keystore_setup_new(&dev_config.keystore)) {
                OK_LOG_INFO("Keystore generated new.");
                commit_pending = true;
                break;
            }
        } while (0);
    }

    // backup to uicr if necessary
    if (!devcfg_keystore_backup_compare(&dev_config.keystore)) {
        OK_LOG_WARN("Keystore backup not match, try to backup.");
        devcfg_keystore_backup_to_uicr(&dev_config.keystore);
    }

    if (commit_pending) {
        ok_device_config_commit();
    }
}

bool ok_device_config_commit(void)
{
    return (ok_flash_write(&dev_config_storage) == OK_FLASH_SUCCESS);
}

ok_devcfg_t *ok_device_config_get(void)
{
    return &dev_config;
}
