#include <stdint.h>
#include "ble.h"
#include "ble_conn_params.h"
#include "nrf_sdh.h"
#include "nrf_sdh_soc.h"
#include "nrf_sdh_ble.h"
#include "nrf_ble_gatt.h"
#include "ble_bas.h"
#include "power_manage.h"
#include "app_timer.h"
#include "ok_ble_internal.h"
#include "ok_platform.h"

#define BATTERY_MEAS_LONG_INTERVAL APP_TIMER_TICKS(5000)

BLE_BAS_DEF(m_bas);
APP_TIMER_DEF(m_battery_timer_id);

static uint8_t g_bas_update_flag = 0;

// battery measurement timeout handler
static void battery_level_meas_timeout_handler(void *p_context)
{
    ret_code_t     err_code;
    static uint8_t battery_percent = 0;

    PMU_t *pwr_ctx_p = power_manage_ctx_get();
    if (pwr_ctx_p == NULL) {
        return;
    }

    UNUSED_PARAMETER(p_context);
    if (battery_percent != pwr_ctx_p->PowerStatus->batteryPercent) {
        battery_percent = pwr_ctx_p->PowerStatus->batteryPercent;
        if (g_bas_update_flag == 1) {
            err_code = ble_bas_battery_level_update(&m_bas, battery_percent, BLE_CONN_HANDLE_ALL);
            if ((err_code != NRF_SUCCESS) && (err_code != NRF_ERROR_INVALID_STATE) && (err_code != NRF_ERROR_RESOURCES) &&
                (err_code != BLE_ERROR_GATTS_SYS_ATTR_MISSING)) {
                APP_ERROR_HANDLER(err_code);
            }
        }
    }
}

/**@brief Function for handling the Battery Service events.
 *
 * @details This function will be called for all Battery Service events which are passed to the
 *          application.
 *
 * @param[in] p_bas  Battery Service structure.
 * @param[in] p_evt  Event received from the Battery Service.
 */
static void on_bas_evt(ble_bas_t *p_bas, ble_bas_evt_t *p_evt)
{
    switch (p_evt->evt_type) {
        case BLE_BAS_EVT_NOTIFICATION_ENABLED:
            g_bas_update_flag = 1;
            break; // BLE_BAS_EVT_NOTIFICATION_ENABLED

        case BLE_BAS_EVT_NOTIFICATION_DISABLED:
            g_bas_update_flag = 0;
            break; // BLE_BAS_EVT_NOTIFICATION_DISABLED

        default:
            // No implementation needed.
            break;
    }
}

// battery measurement timer init
void ok_bas_timer_init(void)
{
    ret_code_t err_code;
    err_code = app_timer_create(&m_battery_timer_id, APP_TIMER_MODE_REPEATED, battery_level_meas_timeout_handler);
    APP_ERROR_CHECK(err_code);
}

void ok_bas_timer_start(void)
{
    ret_code_t err_code;
    err_code = app_timer_start(m_battery_timer_id, BATTERY_MEAS_LONG_INTERVAL, NULL);
    APP_ERROR_CHECK(err_code);
}

// battery service init
void ok_bas_service_init(void)
{
    uint32_t       err_code;
    ble_bas_init_t bas_init;

    // Here the sec level for the Battery Service can be changed/increased.
    bas_init.bl_rd_sec        = SEC_OPEN;
    bas_init.bl_cccd_wr_sec   = SEC_OPEN;
    bas_init.bl_report_rd_sec = SEC_OPEN;

    bas_init.evt_handler          = on_bas_evt;
    bas_init.support_notification = true;
    bas_init.p_report_ref         = NULL;
    bas_init.initial_batt_level   = 100;

    err_code = ble_bas_init(&m_bas, &bas_init);
    APP_ERROR_CHECK(err_code);
}
