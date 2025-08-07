#include <stdint.h>
#include "ble.h"
#include "ble_conn_params.h"
#include "nrf_sdh.h"
#include "nrf_sdh_soc.h"
#include "nrf_sdh_ble.h"

#include "ble_advdata.h"
#include "ble_advertising.h"
#include "ble_fido.h"
#include "ble_nus.h"
#include "ble_srv_common.h"

#include "ok_platform.h"
#include "ok_ble_internal.h"

#define APP_ADV_INTERVAL 40 /**< The advertising interval (in units of 0.625 ms. This value corresponds to 25 ms). */
#define APP_ADV_DURATION 0  /**< The advertising duration (180 seconds) in units of 10 milliseconds. */

BLE_ADVERTISING_DEF(m_advertising);

static ble_uuid_t m_adv_uuids[] = {
#if BLE_DIS_ENABLED
    {BLE_UUID_DEVICE_INFORMATION_SERVICE, BLE_UUID_TYPE_BLE},
#endif
    {BLE_UUID_BATTERY_SERVICE, BLE_UUID_TYPE_BLE},
    {BLE_UUID_FIDO_SERVICE, BLE_UUID_TYPE_BLE},
    {BLE_UUID_NUS_SERVICE, BLE_UUID_TYPE_BLE}};

static volatile uint8_t ok_ble_adv_onoff_status = 1;

static void on_adv_evt(ble_adv_evt_t ble_adv_evt)
{
    switch (ble_adv_evt) {
        case BLE_ADV_EVT_IDLE:
            NRF_LOG_INFO("ble_adv_evt_t -> BLE_ADV_EVT_IDLE");
            break;
        case BLE_ADV_EVT_FAST:
            NRF_LOG_INFO("ble_adv_evt_t -> BLE_ADV_EVT_FAST");
            break;

        default:
            break;
    }
}

// 0-off 1-on
void ok_ble_adv_onoff_set(uint8_t onoff)
{
    ok_ble_adv_onoff_status = onoff;
}

uint8_t ok_ble_adv_onoff_get(void)
{
    return ok_ble_adv_onoff_status;
}

void ok_ble_adv_init(void)
{
    uint32_t               err_code;
    ble_advertising_init_t init;

    memset(&init, 0, sizeof(init));

    init.advdata.name_type               = BLE_ADVDATA_FULL_NAME;
    init.advdata.include_appearance      = false;
    init.advdata.flags                   = BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE;
    init.advdata.uuids_complete.uuid_cnt = sizeof(m_adv_uuids) / sizeof(m_adv_uuids[0]);
    init.advdata.uuids_complete.p_uuids  = m_adv_uuids;

    init.config.ble_adv_fast_enabled  = true;
    init.config.ble_adv_fast_interval = APP_ADV_INTERVAL;
    init.config.ble_adv_fast_timeout  = APP_ADV_DURATION;

    init.evt_handler = on_adv_evt;

    err_code = ble_advertising_init(&m_advertising, &init);
    APP_ERROR_CHECK(err_code);

    ble_advertising_conn_cfg_tag_set(&m_advertising, APP_BLE_CONN_CFG_TAG);
}

void ok_ble_adv_ctrl(uint8_t enable)
{
    if (enable) {
        ble_advertising_start(&m_advertising, BLE_ADV_MODE_FAST);
    } else {
        // stop ble adv
        ble_advertising_stop(&m_advertising);
    }
}

void ok_ble_adv_process(void)
{
    // default setting: ble advertising start when power on
    static bool b_adv_set_poweron = false;
    if (!b_adv_set_poweron) {
        ok_ble_adv_ctrl(1);
        ok_ble_adv_onoff_status = 1;
        b_adv_set_poweron       = true;
    }

    ok_devcfg_t *devcfg = ok_device_config_get();
    if (devcfg->settings.flag_initialized == DEVICE_CONFIG_FLAG_MAGIC) {
        if (devcfg->settings.bt_ctrl != DEVICE_CONFIG_FLAG_MAGIC && ok_ble_adv_onoff_status == 0) {
            NRF_LOG_INFO("ble adv start.");
            ok_ble_adv_ctrl(1);
            return;
        }

        if (devcfg->settings.bt_ctrl == DEVICE_CONFIG_FLAG_MAGIC && ok_ble_adv_onoff_status) {
            NRF_LOG_INFO("ble adv stop.");
            ok_ble_adv_ctrl(0);
            return;
        }
    }
}
