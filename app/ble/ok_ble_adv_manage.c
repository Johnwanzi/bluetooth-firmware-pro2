/*
 * Copyright (c) 2021-2025, Onekey Hardware Team
 *
 * @brief advertising management of Onekey and MFi bluetooth
 *
 * Change Logs:
 * Date           Author            Notes
 * 2025-06-22     John         first version
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "app_timer.h"
#include "ble.h"
#include "ble_gap.h"
#include "ble_advdata.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
#include "ok_ble.h"

#define BLE_ADV_MANAGE_TIMEOUT_MS   APP_TIMER_TICKS(1500) // 1500ms
#define BLE_ADV_WAKEUP_IMMEDIATE_MS APP_TIMER_TICKS(20)   // 20ms

#ifdef FMNA_ADV_TX_POWER_DBM
#define BLE_ADV_TX_POWER_DBM FMNA_ADV_TX_POWER_DBM
#else
#define BLE_ADV_TX_POWER_DBM 4
#endif

#ifdef FMNA_BLE_CONN_CFG_TAG
#define BLE_CONN_TAG FMNA_BLE_CONN_CFG_TAG
#else
#define BLE_CONN_TAG 1
#endif

APP_TIMER_DEF(m_adv_timer);

static ble_adv_manage_t m_ble_adv_manage = {0};

static void ble_adv_manage_start(uint8_t idx)
{
    uint32_t       ret_code         = 0;
    uint8_t        null_mac_addr[6] = {0};
    ble_gap_addr_t gap_addr         = {0};

    NRF_LOG_INFO("Advertising instance %d started", idx);

    if (memcmp(null_mac_addr, m_ble_adv_manage.adv[idx].mac, 6)) {
        // use provided mac address
        sd_ble_gap_addr_get(&gap_addr);
        memcpy(gap_addr.addr, m_ble_adv_manage.adv[idx].mac, sizeof(gap_addr.addr));
        sd_ble_gap_addr_set(&gap_addr);
    }

    // NRF_LOG_INFO("Adv data: %d bytes", m_ble_adv_manage.adv[idx].adv_data.adv_data.len);
    // NRF_LOG_HEXDUMP_INFO(m_ble_adv_manage.adv[idx].adv_data.adv_data.p_data, m_ble_adv_manage.adv[idx].adv_data.adv_data.len);

    ret_code = sd_ble_gap_adv_set_configure(&m_ble_adv_manage.adv_handle, &m_ble_adv_manage.adv[idx].adv_data, &m_ble_adv_manage.adv[idx].adv_params);
    APP_ERROR_CHECK(ret_code);

    ret_code = sd_ble_gap_tx_power_set(BLE_GAP_TX_POWER_ROLE_ADV, m_ble_adv_manage.adv_handle, BLE_ADV_TX_POWER_DBM);
    APP_ERROR_CHECK(ret_code);

    // start advertising
    ret_code = sd_ble_gap_adv_start(m_ble_adv_manage.adv_handle, BLE_CONN_TAG);
    APP_ERROR_CHECK(ret_code);
}

static void ble_adv_manage_timeout_handler(void *p_context)
{
    static uint8_t adv_index = 0;
    // no advertising instances are running, stop the timer
    if (m_ble_adv_manage.adv_alive_num == 0) {
        app_timer_stop(m_ble_adv_manage.adv_timer.adv_timer_id);
        return;
    }

    // stop advertising first
    if (m_ble_adv_manage.adv_is_running) {
        NRF_LOG_INFO("Advertising stopped");
        sd_ble_gap_adv_stop(m_ble_adv_manage.adv_handle);
        m_ble_adv_manage.adv_is_running = false;
    }

    // adv_index represents the next advertising instance index
    if (p_context != NULL) {
        adv_index = (*(uint8_t *)p_context) % BLE_INSTANCE_NUM;
    } else {
        adv_index = (adv_index + 1) % BLE_INSTANCE_NUM;
        // check if the next instance is alive and not connected
        if (!m_ble_adv_manage.adv[adv_index].adv_alive || m_ble_adv_manage.adv[adv_index].conn_handle != BLE_CONN_HANDLE_INVALID) {
            adv_index = (adv_index + 1) % BLE_INSTANCE_NUM;
        }
    }

    // start the next advertising instance
    if (m_ble_adv_manage.adv[adv_index].adv_alive && m_ble_adv_manage.adv[adv_index].conn_handle == BLE_CONN_HANDLE_INVALID) {
        ble_adv_manage_start(adv_index);
        m_ble_adv_manage.adv_is_running = true;
    }

    if (m_ble_adv_manage.adv_alive_num > 1) {
        app_timer_start(m_ble_adv_manage.adv_timer.adv_timer_id, BLE_ADV_MANAGE_TIMEOUT_MS, NULL);
    }
}

void ble_adv_manage_stop_broadcast(void)
{
    sd_ble_gap_adv_stop(m_ble_adv_manage.adv_handle);
}

void ble_adv_manage_register(uint8_t instance_id, ble_adv_instance_t *adv_config, bool start_adv_immediately)
{
    static uint8_t s_current_instance_id = 0;

    // Validate the instance ID and check if advertising management is initialized
    if (instance_id >= BLE_INSTANCE_NUM || !m_ble_adv_manage.adv_is_managed) {
        return;
    }

    // stop the previous advertising instance first, in case the RTC interupt is triggered when modifying the next instance.
    app_timer_stop(m_ble_adv_manage.adv_timer.adv_timer_id);

    m_ble_adv_manage.adv[instance_id].conn_handle = BLE_CONN_HANDLE_INVALID;

    if (adv_config) {
        m_ble_adv_manage.adv[instance_id].adv_data        = adv_config->adv_data;
        m_ble_adv_manage.adv[instance_id].adv_params      = adv_config->adv_params;
        m_ble_adv_manage.adv[instance_id].ble_evt_handler = adv_config->ble_evt_handler;
        memcpy(m_ble_adv_manage.adv[instance_id].mac, adv_config->mac, sizeof(m_ble_adv_manage.adv[instance_id].mac));
    }

    if (!m_ble_adv_manage.adv[instance_id].adv_alive) {
        m_ble_adv_manage.adv_alive_num++;
        m_ble_adv_manage.adv[instance_id].adv_alive = true;
    }

    s_current_instance_id = instance_id;

    if (start_adv_immediately) {
        app_timer_start(m_ble_adv_manage.adv_timer.adv_timer_id, BLE_ADV_WAKEUP_IMMEDIATE_MS, &s_current_instance_id);
    }
}

void ble_adv_manage_unregister(uint8_t instance_id, bool stop_adv)
{
    // Validate the instance ID and check if advertising management is initialized
    if (instance_id >= BLE_INSTANCE_NUM || !m_ble_adv_manage.adv_is_managed) {
        return;
    }

    if (m_ble_adv_manage.adv[instance_id].adv_alive) {
        m_ble_adv_manage.adv[instance_id].adv_alive = false;
        m_ble_adv_manage.adv_alive_num--;
    }

    if (stop_adv) {
        app_timer_stop(m_ble_adv_manage.adv_timer.adv_timer_id);
    }
}

void ble_adv_manage_update(uint8_t instance_id, uint8_t data_type, void *data)
{
    if (instance_id >= BLE_INSTANCE_NUM || !m_ble_adv_manage.adv_is_managed || data == NULL) {
        return;
    }

    if (!m_ble_adv_manage.adv[instance_id].adv_alive) {
        NRF_LOG_WARNING("Cannot update advertising data while not existing");
        return;
    }

    if (m_ble_adv_manage.adv[instance_id].conn_handle == BLE_CONN_HANDLE_INVALID) {
        app_timer_stop(m_ble_adv_manage.adv_timer.adv_timer_id);
    }

    switch (data_type) {
        case BLE_MANAGE_UPDATE_ADV_DATA:
        case BLE_MANAGE_UPDATE_ADV_PARAMS: {
            ble_gap_adv_params_t *adv_params = (ble_gap_adv_params_t *)data;
            memcpy(&m_ble_adv_manage.adv[instance_id].adv_params, adv_params, sizeof(ble_gap_adv_params_t));
        } break;

        case BLE_MANAGE_UPDATE_ADV_TOTAL: {
            ble_adv_instance_t *adv_config = (ble_adv_instance_t *)data;

            m_ble_adv_manage.adv[instance_id].adv_data   = adv_config->adv_data;
            m_ble_adv_manage.adv[instance_id].adv_params = adv_config->adv_params;
        } break;

        case BLE_MANAGE_UPDATE_MAC_ADDR: {
        } break;

        case BLE_MANAGE_UPDATE_EVT_HANDLER: {
            void (*evt_handler)(ble_evt_t const *)            = (void (*)(ble_evt_t const *))data;
            m_ble_adv_manage.adv[instance_id].ble_evt_handler = evt_handler;
        } break;

        default:
            break;
    }

    if (m_ble_adv_manage.adv[instance_id].conn_handle == BLE_CONN_HANDLE_INVALID) {
        app_timer_start(m_ble_adv_manage.adv_timer.adv_timer_id, BLE_ADV_WAKEUP_IMMEDIATE_MS, NULL);
    }
}

void ble_adv_manage_event(ble_evt_t const *p_ble_evt)
{
    static uint8_t s_next_adv_index = 0;

    if (p_ble_evt == NULL) {
        return;
    }

    switch (p_ble_evt->header.evt_id) {
        case BLE_GAP_EVT_CONNECTED: {
            for (uint8_t adv_index = 0; adv_index < BLE_INSTANCE_NUM; adv_index++) {
                if (p_ble_evt->evt.gap_evt.params.connected.adv_data.adv_data.p_data == m_ble_adv_manage.adv[adv_index].adv_data.adv_data.p_data) {
                    NRF_LOG_INFO("index %d Connected", adv_index);
                    m_ble_adv_manage.adv[adv_index].conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
                    app_timer_stop(m_ble_adv_manage.adv_timer.adv_timer_id);
                    app_timer_start(m_ble_adv_manage.adv_timer.adv_timer_id, BLE_ADV_WAKEUP_IMMEDIATE_MS, NULL);
                    break;
                }
            }
        } break;

        case BLE_GAP_EVT_DISCONNECTED: {
            for (uint8_t adv_index = 0; adv_index < BLE_INSTANCE_NUM; adv_index++) {
                if (p_ble_evt->evt.gap_evt.conn_handle == m_ble_adv_manage.adv[adv_index].conn_handle) {
                    NRF_LOG_INFO("index %d Disconnected", adv_index);
                    m_ble_adv_manage.adv[adv_index].conn_handle = BLE_CONN_HANDLE_INVALID;

                    if (m_ble_adv_manage.adv[adv_index].ble_evt_handler) {
                        m_ble_adv_manage.adv[adv_index].ble_evt_handler(p_ble_evt);
                    }

                    s_next_adv_index                            = adv_index;
                    app_timer_stop(m_ble_adv_manage.adv_timer.adv_timer_id);
                    app_timer_start(m_ble_adv_manage.adv_timer.adv_timer_id, BLE_ADV_WAKEUP_IMMEDIATE_MS, &s_next_adv_index);
                    break;
                }
            }
        } break;

        case BLE_GAP_EVT_ADV_SET_TERMINATED: {
            NRF_LOG_INFO("switch to slow advertising");
            extern void fmna_adv_platform_start_slow_adv(void);
            fmna_adv_platform_start_slow_adv();
        } break;

        default:
            break;
    }

    if (p_ble_evt->evt.gap_evt.conn_handle == m_ble_adv_manage.adv[BLE_ONEKEY_ADV_E].conn_handle) {
        NRF_LOG_INFO("Onekey ble event %d", p_ble_evt->header.evt_id);
        if (m_ble_adv_manage.adv[BLE_ONEKEY_ADV_E].ble_evt_handler) {
            m_ble_adv_manage.adv[BLE_ONEKEY_ADV_E].ble_evt_handler(p_ble_evt);
        }
    }

    if (p_ble_evt->evt.gap_evt.conn_handle == m_ble_adv_manage.adv[BLE_MFI_ADV_E].conn_handle) {
        NRF_LOG_INFO("MFi ble event %d", p_ble_evt->header.evt_id);
        if (m_ble_adv_manage.adv[BLE_MFI_ADV_E].ble_evt_handler) {
            m_ble_adv_manage.adv[BLE_MFI_ADV_E].ble_evt_handler(p_ble_evt);
        }
    }
}

void ble_adv_manage_init(void)
{
    uint32_t ret_code = 0;
    NRF_LOG_INFO("enter ble_adv_manage_init");

    // Check if already initialized
    if (m_ble_adv_manage.adv_is_managed) {
        return;
    }

    // Initialize the advertising management structure
    m_ble_adv_manage.adv_is_running              = false;
    m_ble_adv_manage.adv_alive_num               = 0;
    m_ble_adv_manage.adv_timer.adv_timeout_ms    = BLE_ADV_MANAGE_TIMEOUT_MS;
    m_ble_adv_manage.adv_timer.adv_timer_id      = m_adv_timer;
    m_ble_adv_manage.adv_timer.adv_timer_handler = ble_adv_manage_timeout_handler;

    ret_code = app_timer_create((const app_timer_id_t *)&m_ble_adv_manage.adv_timer.adv_timer_id, APP_TIMER_MODE_SINGLE_SHOT,
                                m_ble_adv_manage.adv_timer.adv_timer_handler);
    APP_ERROR_CHECK(ret_code);

    m_ble_adv_manage.adv_is_managed = true;
}
