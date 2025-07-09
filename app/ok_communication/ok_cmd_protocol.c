#include <stdint.h>
#include <string.h>
#include "app_error.h"
#include "ble_gap.h"
#include "nrf_crypto_hash.h"
#include "app_scheduler.h"

#include "firmware_config.h"
#include "device_config.h"
#include "ok_cmd_protocol.h"
#include "ok_platform.h"
#include "ok_pwr_manage.h"
#include "ok_ble.h"
#include "ok_flashled.h"
#include "ok_communication.h"

#ifndef BUILD_ID
#define BUILD_ID "unknown"
#endif

#define OK_CMD_TYPE_NO_PAYLOAD   0x01
#define OK_CMD_TYPE_WITH_PAYLOAD 0x02

typedef struct {
    uint8_t cmd_type;
    uint8_t main_cmd;
    void (*cmd_parse_handler)(void *data, uint16_t length);
} ok_command_protocol_t;

// STM-MCU -> BLE-MCU
static void ok_cmd_uplink_ble_ctrl_handler(void *data, uint16_t length);
static void ok_cmd_uplink_pwr_ctrl_handler(void *data, uint16_t length);
static void ok_cmd_uplink_ble_info_handler(void *data, uint16_t length);
static void ok_cmd_uplink_reset_handler(void *data, uint16_t length);
static void ok_cmd_uplink_flashled_handler(void *data, uint16_t length);
static void ok_cmd_uplink_ble_bat_info(void *data, uint16_t length);
static void ok_cmd_uplink_ble_sign_handler(void *data, uint16_t length);

static ok_command_protocol_t ok_cmd_table[] = {
    // request: STM-MCU -> BLE-MCU
    {OK_CMD_TYPE_NO_PAYLOAD,    OK_UPLINK_MAIN_CMD_BLE_CTRL,      ok_cmd_uplink_ble_ctrl_handler},
    {OK_CMD_TYPE_NO_PAYLOAD,    OK_UPLINK_MAIN_CMD_POWER_CTRL,    ok_cmd_uplink_pwr_ctrl_handler},
    {OK_CMD_TYPE_NO_PAYLOAD,    OK_UPLINK_MAIN_CMD_BLE_INFO,      ok_cmd_uplink_ble_info_handler},
    {OK_CMD_TYPE_NO_PAYLOAD,    OK_UPLINK_MAIN_CMD_RESET,         ok_cmd_uplink_reset_handler},
    {OK_CMD_TYPE_NO_PAYLOAD,    OK_UPLINK_MAIN_CMD_FLASHLED,      ok_cmd_uplink_flashled_handler},
    {OK_CMD_TYPE_NO_PAYLOAD,    OK_UPLINK_MAIN_CMD_BAT_STATUS,    ok_cmd_uplink_ble_bat_info},
    {OK_CMD_TYPE_NO_PAYLOAD,    OK_UPLINK_MAIN_CMD_SIGN,          ok_cmd_uplink_ble_sign_handler},
};

// MCU -> BLE
static void ok_cmd_uplink_ble_ctrl_handler(void *data, uint16_t length)
{
    uint8_t sub_cmd     = 0;
    uint8_t rsp_len     = 0;
    uint8_t bak_buff[4] = {0};

    if (data == NULL || length == 0) {
        return;
    }

    sub_cmd = *(uint8_t *)data;
    OK_LOG_INFO("enter ok_cmd_uplink_ble_ctrl_handler %d", sub_cmd);

    if (sub_cmd == OK_UPLINK_SUB_CMD_BLE_TURN_ON) {

        ok_ble_adv_onoff_set(1);
        deviceConfig_p->settings.bt_ctrl = 0;
        device_config_commit();

        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_BLE_STATUS;
        bak_buff[1] = OK_DOWNLINK_SUB_CMD_BLE_TURN_ON;
        rsp_len     = 2;

    } else if (sub_cmd == OK_UPLINK_SUB_CMD_BLE_TURN_OFF) {

        ok_ble_adv_onoff_set(0);
        deviceConfig_p->settings.bt_ctrl = DEVICE_CONFIG_FLAG_MAGIC;
        device_config_commit();

        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_BLE_STATUS;
        bak_buff[1] = OK_DOWNLINK_SUB_CMD_BLE_TURN_OFF;
        rsp_len     = 2;

    } else if (sub_cmd == OK_UPLINK_SUB_CMD_BLE_DISCONNECT) {
        
        ok_ble_gap_local_disconnect();
        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_BLE_STATUS;
        bak_buff[1] = OK_DOWNLINK_SUB_CMD_BLE_DISCONNECTED;
        rsp_len     = 2;

    } else if (sub_cmd == OK_UPLINK_SUB_CMD_BLE_GET_STATUS) {

        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_BLE_STATUS;
        bak_buff[1] = ok_ble_adv_onoff_get() ? OK_DOWNLINK_SUB_CMD_BLE_TURN_ON : OK_DOWNLINK_SUB_CMD_BLE_TURN_OFF;
        rsp_len     = 2;

    }

    if (rsp_len > 0) {
        ok_send_stm_data(bak_buff, rsp_len);
    }
}

static void ok_cmd_uplink_pwr_ctrl_handler(void *data, uint16_t length)
{
    uint8_t sub_cmd     = 0;
    uint8_t rsp_len     = 0;
    uint8_t bak_buff[4] = {0};

    if (data == NULL || length == 0) {
        return;
    }

    sub_cmd = *(uint8_t *)data;
    OK_LOG_INFO("enter ok_cmd_uplink_pwr_ctrl_handler %d", sub_cmd);

    PMU_t *pmu_p = power_manage_ctx_get();

    if (sub_cmd == OK_UPLINK_SUB_CMD_SYS_POWER_TURN_OFF) {
        // TODO1K turn off ble
        pmu_p->SetState(PWR_STATE_HARD_OFF);
    } else if (sub_cmd == OK_UPLINK_SUB_CMD_EMMC_POWER_TURN_OFF) {
    } else if (sub_cmd == OK_UPLINK_SUB_CMD_EMCC_POWER_TURN_ON) {
    } else if (sub_cmd == OK_UPLINK_SUB_CMD_POWER_PERCENT_GET) {
        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_POWER_PERCENT;
        bak_buff[1] = pmu_p->PowerStatus->batteryPercent;
        rsp_len     = 2;
    } else if (sub_cmd == OK_UPLINK_SUB_CMD_USB_POWER_STATUS_GET) {
        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_POWER_MANAGE;

        if (pmu_p->PowerStatus->chargerAvailable) {
            bak_buff[1] = OK_DOWNLINK_SUB_CMD_POWER_CHARGING;
            bak_buff[2] = (pmu_p->PowerStatus->wiredCharge ? CHARGE_TYPE_USB : CHARGE_TYPE_WIRELESS);
        } else {
            bak_buff[1] = OK_DOWNLINK_SUB_CMD_POWER_DISCONNECT;
            bak_buff[2] = 0;
        }

        rsp_len = 3;
    } else if (sub_cmd == OK_UPLINK_SUB_CMD_CHARGE_ENABLE) {
        ok_pmu_charge_ctrl(1);
    } else if (sub_cmd == OK_UPLINK_SUB_CMD_CHARGE_DISABLE) {
        ok_pmu_charge_ctrl(0);
    }

    if (rsp_len > 0) {
        ok_send_stm_data(bak_buff, rsp_len);
    }
}

static void ok_cmd_uplink_ble_info_handler(void *data, uint16_t length)
{
    uint8_t sub_cmd      = 0;
    uint8_t rsp_len      = 0;
    uint8_t bak_buff[48] = {0};

    if (data == NULL || length == 0) {
        return;
    }

    sub_cmd = *(uint8_t *)data;
    OK_LOG_INFO("enter ok_cmd_uplink_ble_info_handler %d", sub_cmd);

    if (sub_cmd == OK_UPLINK_SUB_CMD_BLE_ADV_NAME_GET) {

        char *adv_name = ok_ble_adv_name_get();
        bak_buff[0]    = OK_DOWNLINK_MAIN_CMD_ADV_NAME;
        memcpy(&bak_buff[1], (uint8_t *)adv_name, strlen(adv_name));
        rsp_len = strlen(adv_name) + 1;

    } else if (sub_cmd == OK_UPLINK_SUB_CMD_BLE_FIRMWARE_VER_GET) {

        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_FW_VERSION;
        memcpy(&bak_buff[1], FW_REVISION, strlen(FW_REVISION));
        rsp_len = strlen(FW_REVISION) + 1;

    } else if (sub_cmd == OK_UPLINK_SUB_CMD_BLE_SD_VER_GET) {

        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_SD_VERSION;
        memcpy(&bak_buff[1], SW_REVISION, strlen(SW_REVISION));
        rsp_len = strlen(SW_REVISION) + 1;

    } else if (sub_cmd == OK_UPLINK_SUB_CMD_BLE_BOOT_VER_GET) {

        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_BOOT_VERSION;
        memcpy(&bak_buff[1], BT_REVISION, strlen(BT_REVISION));
        rsp_len = strlen(BT_REVISION) + 1;

    } else if (sub_cmd == OK_UPLINK_SUB_CMD_BLE_BUILD_ID_GET) {

        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_BUILD_ID;
        memcpy(&bak_buff[1], (uint8_t *)BUILD_ID, strlen(BUILD_ID));
        rsp_len = strlen(BUILD_ID) + 1;

    } else if (sub_cmd == OK_UPLINK_SUB_CMD_BLE_HASH_GET) {
        ret_code_t err_code  = NRF_SUCCESS;
        uint8_t    hash[32]  = {0};
        size_t     hash_len  = 32;
        int        chunks    = 0;
        int        app_size  = 0;
        uint8_t   *code_addr = (uint8_t *)0x26000;
        uint8_t   *code_len  = (uint8_t *)0x7F018;
        app_size             = code_len[0] + code_len[1] * 256 + code_len[2] * 256 * 256;
        chunks               = app_size / 512;

        nrf_crypto_backend_hash_context_t hash_context = {0};

        err_code = nrf_crypto_hash_init(&hash_context, &g_nrf_crypto_hash_sha256_info);
        APP_ERROR_CHECK(err_code);

        for (int i = 0; i < chunks; i++) {
            err_code = nrf_crypto_hash_update(&hash_context, code_addr + i * 512, 512);
            APP_ERROR_CHECK(err_code);
        }

        if (app_size % 512) {
            err_code = nrf_crypto_hash_update(&hash_context, code_addr + chunks * 512, app_size % 512);
            APP_ERROR_CHECK(err_code);
        }

        err_code = nrf_crypto_hash_finalize(&hash_context, hash, &hash_len);
        APP_ERROR_CHECK(err_code);

        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_HASH;
        memcpy(&bak_buff[1], hash, sizeof(hash));
        rsp_len = sizeof(hash) + 1;

    } else if (sub_cmd == OK_UPLINK_SUB_CMD_BLE_MAC_GET) {

        ble_gap_addr_t gap_addr;
        sd_ble_gap_addr_get(&gap_addr);

        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_BLE_MAC;
        memcpy(&bak_buff[1], (uint8_t *)gap_addr.addr, BLE_GAP_ADDR_LEN);
        rsp_len = BLE_GAP_ADDR_LEN + 1;
    }

    if (rsp_len > 0) {
        ok_send_stm_data(bak_buff, rsp_len);
    }
}

static void ok_cmd_uplink_reset_handler(void *data, uint16_t length)
{
    NVIC_SystemReset();
}

static void ok_cmd_uplink_flashled_handler(void *data, uint16_t length)
{
    uint8_t sub_cmd          = 0;
    uint8_t rsp_len          = 0;
    uint8_t bak_buff[4]      = {0};
    uint8_t s_led_brightness = 0;

    if (data == NULL || length == 0) {
        return;
    }

    sub_cmd = *(uint8_t *)data;
    OK_LOG_INFO("enter ok_cmd_uplink_flashled_handler %d", sub_cmd);

    if (sub_cmd == OK_UPLINK_SUB_CMD_FLASHLED_SET) {
        s_led_brightness = *(uint8_t *)(data + 1);

        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_FLASHLED_CTRL;
        bak_buff[1] = OK_UPLINK_SUB_CMD_FLASHLED_SET;
        bak_buff[2] = s_led_brightness;
        rsp_len     = 3;

        set_led_brightness(s_led_brightness);

    } else if (sub_cmd == OK_UPLINK_SUB_CMD_FLASHLED_GET) {

        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_FLASHLED_CTRL;
        bak_buff[1] = OK_UPLINK_SUB_CMD_FLASHLED_GET;
        bak_buff[2] = s_led_brightness;
        rsp_len     = 3;
    }

    if (rsp_len > 0) {
        ok_send_stm_data(bak_buff, rsp_len);
    }
}

static void ok_cmd_uplink_ble_bat_info(void *data, uint16_t length)
{
    uint8_t  sub_cmd     = 0;
    uint8_t  rsp_len     = 0;
    uint16_t val         = 0;
    uint8_t  bak_buff[4] = {0};

    if (data == NULL || length == 0) {
        return;
    }

    sub_cmd = *(uint8_t *)data;
    OK_LOG_INFO("enter ok_cmd_uplink_ble_bat_info %d", sub_cmd);

    PMU_t *pmu_p = power_manage_ctx_get();

    if (sub_cmd == OK_UPLINK_SUB_CMD_BAT_VOL) {
        val = pmu_p->PowerStatus->batteryVoltage;
    } else if (sub_cmd == OK_UPLINK_SUB_CMD_BAT_CHARGE_CURRENT) {
        val = pmu_p->PowerStatus->chargeCurrent;
    } else if (sub_cmd == OK_UPLINK_SUB_CMD_BAT_DISCHARGE_CURRENT) {
        val = pmu_p->PowerStatus->dischargeCurrent;
    } else if (sub_cmd == OK_UPLINK_SUB_CMD_BAT_INNER_TEMP) {
        val = (uint16_t)(pmu_p->PowerStatus->batteryTemp);
    } else {
        return;
    }

    bak_buff[0] = OK_DOWNLINK_MAIN_CMD_BAT_INFO;
    bak_buff[1] = sub_cmd;
    bak_buff[2] = val >> 8;
    bak_buff[3] = val & 0xFF;
    rsp_len     = 4;

    if (rsp_len > 0) {
        ok_send_stm_data(bak_buff, rsp_len);
    }
}

static void ok_cmd_uplink_ble_sign_handler(void *data, uint16_t length)
{
#define SIGN_PUBKEY_SUCCESS 0
#define SIGN_PUBKEY_FAILED  1
#define SIGN_PUBKEY_DATA    2
#define SIGN_DATA           3
    uint8_t sub_cmd      = 0;
    uint8_t rsp_len      = 0;
    uint8_t bak_buff[80] = {0};

    if (data == NULL || length == 0) {
        return;
    }

    sub_cmd = *(uint8_t *)data;
    OK_LOG_INFO("enter ok_cmd_uplink_ble_sign_handler %d", sub_cmd);

    if (sub_cmd == OK_UPLINK_SUB_CMD_BLE_PUBKEY) {
        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_SIGN;
        if (deviceConfig_p->keystore.flag_locked == DEVICE_CONFIG_FLAG_MAGIC) {
            bak_buff[1] = SIGN_PUBKEY_FAILED; /* failed */
            rsp_len     = 2;
        } else if (!deviceCfg_keystore_validate(&(deviceConfig_p->keystore))) {
            bak_buff[1] = SIGN_PUBKEY_FAILED;
            rsp_len     = 2;
        } else {
            bak_buff[1] = SIGN_PUBKEY_DATA; /* success */
            memcpy(&bak_buff[2], deviceConfig_p->keystore.public_key, sizeof(deviceConfig_p->keystore.public_key));
            rsp_len = sizeof(deviceConfig_p->keystore.public_key) + 2;
        }
    } else if (sub_cmd == OK_UPLINK_SUB_CMD_BLE_PUBKEY_LOCK) {
        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_SIGN;
        bak_buff[1] = (deviceCfg_keystore_lock(&(deviceConfig_p->keystore)) && device_config_commit()) ? SIGN_PUBKEY_SUCCESS : SIGN_PUBKEY_FAILED;

        rsp_len = 2;
    } else if (sub_cmd == OK_UPLINK_SUB_CMD_BLE_SIGN_REQUEST) {
        bak_buff[0] = OK_DOWNLINK_MAIN_CMD_SIGN;

        if (!deviceCfg_keystore_validate(&(deviceConfig_p->keystore))) {
            bak_buff[1] = SIGN_PUBKEY_FAILED;
            rsp_len     = 2;
        } else {
            bak_buff[1] = SIGN_DATA;
            if (deviceConfig_p->keystore.flag_locked != DEVICE_CONFIG_FLAG_MAGIC) {
                deviceCfg_keystore_lock(&(deviceConfig_p->keystore));
                device_config_commit();
            }
            /* sub_cmd + payload */
            sign_ecdsa_msg(deviceConfig_p->keystore.private_key, (uint8_t *)data + 1, length - 1, bak_buff + 2);
            rsp_len = 64 + 2;
        }
    }

    if (rsp_len > 0) {
        ok_send_stm_data(bak_buff, rsp_len);
    }
}

void ok_cmd_parse(uint8_t *data, uint16_t length)
{
    uint8_t main_cmd = 0;

    if (data == NULL || length == 0) {
        return;
    }

    main_cmd = data[0];

    for (uint8_t i = 0; i < sizeof(ok_cmd_table) / sizeof(ok_command_protocol_t); i++) {
        if (ok_cmd_table[i].main_cmd == main_cmd) {
            // ok_cmd_table[i].handler(data, length);
            app_sched_event_put(data + 1, length - 1, ok_cmd_table[i].cmd_parse_handler);
            break;
        }
    }
}
