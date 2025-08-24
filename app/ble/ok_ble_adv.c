#include <stdint.h>
#include "ble.h"
#include "ble_conn_params.h"
#include "nrf_sdh.h"
#include "nrf_sdh_soc.h"
#include "nrf_sdh_ble.h"

#include "ble_advdata.h"
#include "ble_fido.h"
#include "ble_nus.h"
#include "ble_srv_common.h"

#include "ok_platform.h"
#include "ok_ble_internal.h"

#define APP_ADV_INTERVAL 64 /**< The advertising interval (in units of 0.625 ms. This value corresponds to 25 ms). */
#define APP_ADV_DURATION 0  /**< The advertising duration (180 seconds) in units of 10 milliseconds. */

static uint8_t m_custom_adv[BLE_GAP_ADV_SET_DATA_SIZE_MAX] = {0};

static ble_uuid_t m_adv_uuids[] = {
#if BLE_DIS_ENABLED
    {BLE_UUID_DEVICE_INFORMATION_SERVICE, BLE_UUID_TYPE_BLE},
#endif
    {BLE_UUID_BATTERY_SERVICE, BLE_UUID_TYPE_BLE},
    {BLE_UUID_FIDO_SERVICE, BLE_UUID_TYPE_BLE},
    {BLE_UUID_NUS_SERVICE, BLE_UUID_TYPE_BLE}
};

static volatile uint8_t ok_ble_adv_onoff_status = 1;

static void ok_ble_evt_handler(ble_evt_t const *p_ble_evt)
{
    ret_code_t err_code;

    switch (p_ble_evt->header.evt_id) {
        case BLE_GAP_EVT_CONNECTED:
            NRF_LOG_INFO("Custom Connected");
            break;

        case BLE_GAP_EVT_DISCONNECTED:
            NRF_LOG_INFO("Custom Disconnected");
            break;

        case BLE_GAP_EVT_SEC_PARAMS_REQUEST:
            // Pairing not supported
            err_code = sd_ble_gap_sec_params_reply(p_ble_evt->evt.gap_evt.conn_handle, BLE_GAP_SEC_STATUS_PAIRING_NOT_SUPP, NULL, NULL);
            APP_ERROR_CHECK(err_code);
            break;

        case BLE_GAP_EVT_PHY_UPDATE_REQUEST: {
            NRF_LOG_DEBUG("Custom PHY update request.");
            ble_gap_phys_t const phys = {
                .rx_phys = BLE_GAP_PHY_AUTO,
                .tx_phys = BLE_GAP_PHY_AUTO,
            };
            err_code = sd_ble_gap_phy_update(p_ble_evt->evt.gap_evt.conn_handle, &phys);
            APP_ERROR_CHECK(err_code);
        } break;

        case BLE_GATTS_EVT_SYS_ATTR_MISSING:
            // No system attributes have been stored.
            err_code = sd_ble_gatts_sys_attr_set(p_ble_evt->evt.gap_evt.conn_handle, NULL, 0, 0);
            APP_ERROR_CHECK(err_code);
            break;

        case BLE_GATTC_EVT_TIMEOUT:
            // Disconnect on GATT Client timeout event.
            NRF_LOG_DEBUG("Custom GATT Client Timeout.");
            err_code = sd_ble_gap_disconnect(p_ble_evt->evt.gattc_evt.conn_handle, BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
            APP_ERROR_CHECK(err_code);
            break;

        case BLE_GATTS_EVT_TIMEOUT:
            // Disconnect on GATT Server timeout event.
            NRF_LOG_DEBUG("Custom GATT Server Timeout.");
            err_code = sd_ble_gap_disconnect(p_ble_evt->evt.gatts_evt.conn_handle, BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
            APP_ERROR_CHECK(err_code);
            break;

        default:
            // No implementation needed.
            break;
    }
}

void ok_ble_adv_init(void)
{
    uint8_t            off           = 0;
    ble_adv_instance_t pair_adv_data = {0};

    NRF_LOG_INFO("ADV onekey Custom...");

    memset(m_custom_adv, 0x00, sizeof(m_custom_adv));

    // config adv data
    m_custom_adv[off++] = 0x02;
    m_custom_adv[off++] = BLE_GAP_AD_TYPE_FLAGS;
    m_custom_adv[off++] = BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE;

    m_custom_adv[off++] = (sizeof(m_adv_uuids) / sizeof(m_adv_uuids[0])) * 2 + 1;
    m_custom_adv[off++] = BLE_GAP_AD_TYPE_16BIT_SERVICE_UUID_COMPLETE;
    for (uint8_t i = 0; i < sizeof(m_adv_uuids) / sizeof(m_adv_uuids[0]); i++) {
        *(uint16_t *)&m_custom_adv[off] = m_adv_uuids[i].uuid;
        off += 2;
    }
    
    uint8_t tmp_len = strlen(ok_ble_adv_name_get());
    m_custom_adv[off++] = tmp_len + 1;
    m_custom_adv[off++] = BLE_GAP_AD_TYPE_COMPLETE_LOCAL_NAME;
    memcpy(&m_custom_adv[off], ok_ble_adv_name_get(), tmp_len);
    off += tmp_len;

    pair_adv_data.adv_data.adv_data.p_data = &m_custom_adv[0];
    pair_adv_data.adv_data.adv_data.len    = off;

    // Configure Advertising module params
    pair_adv_data.adv_params.properties.type = BLE_GAP_ADV_TYPE_CONNECTABLE_SCANNABLE_UNDIRECTED;
    pair_adv_data.adv_params.interval        = APP_ADV_INTERVAL;
    pair_adv_data.adv_params.duration        = APP_ADV_DURATION;
    pair_adv_data.adv_params.filter_policy   = BLE_GAP_ADV_FP_ANY;
    pair_adv_data.adv_params.primary_phy     = BLE_GAP_PHY_AUTO;
    pair_adv_data.ble_evt_handler            = ok_ble_evt_handler;

    ble_adv_manage_register(BLE_ONEKEY_ADV_E, &pair_adv_data, false);
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

void ok_ble_adv_ctrl(uint8_t enable)
{
    if (enable) {
        ble_adv_manage_register(BLE_ONEKEY_ADV_E, NULL, true);
    } else {
        // stop ble adv
        ble_adv_manage_unregister(BLE_ONEKEY_ADV_E, false);
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
