#ifndef __OK_DEVICE_CONFIG_H__
#define __OK_DEVICE_CONFIG_H__

#include <stdint.h>
#include <stdbool.h>

#define DEVICE_CONFIG_HEADER_MAGIC  0xAAAAAAAAU
#define DEVICE_CONFIG_FLAG_MAGIC    0xa55aa55aU
#define DEVICE_CONFIG_START_ADDR    0x6A000
#define DEVICE_CONFIG_END_ADDR      0x6AFFF
#define DEVICE_CONFIG_VERSION       1

typedef struct {
    uint32_t crc32;
    uint32_t flag_locked;
    uint8_t private_key[32];
    uint8_t public_key[64];
} ok_devcfg_keystore_t;

typedef struct {
    uint32_t flag_initialized;
    uint32_t bt_ctrl;
} ok_devcfg_settings_t;

typedef struct {
    uint32_t header;
    uint32_t version;

    ok_devcfg_keystore_t keystore;
    ok_devcfg_settings_t settings;
} ok_devcfg_t;

bool ok_device_config_commit(void);
void ok_device_config_init(void);
bool ok_devcfg_keystore_validate(ok_devcfg_keystore_t* keystore);
bool ok_devcfg_keystore_lock(ok_devcfg_keystore_t* keystore);
ok_devcfg_t *ok_device_config_get(void);


#endif  //__OK_DEVICE_CONFIG_H__
