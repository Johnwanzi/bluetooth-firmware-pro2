#include <stdint.h>
#include <string.h>
#include "app_error.h"
#include "app_timer.h"
#include "nrf_sdh.h"
#include "nrf_sdh_ble.h"
#include "nrf_sdh_soc.h"
#include "nrf_ble_lesc.h"
#include "peer_manager.h"
#include "peer_manager_handler.h"
#include "app_scheduler.h"
#include "ble_conn_state.h"

#include "ok_platform.h"
#include "ok_ble_internal.h"
#include "ok_communication.h"
#include "ok_cmd_protocol.h"
#include "ok_ble.h"

#define SEC_PARAM_BOND            1 /**< Perform bonding. */
#define SEC_PARAM_MITM            1 /**< Man In The Middle protection required (applicable when display module is detected). */
#define SEC_PARAM_LESC            1 /**< LE Secure Connections enabled. */
#define SEC_PARAM_KEYPRESS        0 /**< Keypress notifications not enabled. */
#define SEC_PARAM_IO_CAPABILITIES BLE_GAP_IO_CAPS_DISPLAY_ONLY /**< Display I/O capabilities. */
#define SEC_PARAM_OOB             0                            /**< Out Of Band data not available. */
#define SEC_PARAM_MIN_KEY_SIZE    7                            /**< Minimum encryption key size. */
#define SEC_PARAM_MAX_KEY_SIZE    16                           /**< Maximum encryption key size. */

#define PASSKEY_LENGTH            6

static pm_peer_id_t m_peer_to_be_deleted    = PM_PEER_ID_INVALID;
static uint8_t      bond_check_key_flag     = 0;
static bool         request_service_changed = false;

static void send_service_changed(void *p_event_data, uint16_t event_size)
{
    uint16_t        conn_handle = 0;
    ret_code_t      err_code;
    static uint16_t start_handle;

    err_code = sd_ble_gatts_initial_user_handle_get(&start_handle);
    if (err_code != NRF_SUCCESS) {
        OK_LOG_ERROR_NOFLUSH("sd_ble_gatts_initial_user_handle_get() returned %s which should not happen.", nrf_strerror_get(err_code));
        return;
    }

    conn_handle = ok_ble_conn_handle_get();

    OK_LOG_INFO_NOFLUSH("conn_handle: 0x%04x, start_handle: 0x%04x", conn_handle, start_handle);
    err_code = sd_ble_gatts_service_changed(conn_handle, start_handle, 0xFFFF);
    if ((err_code == BLE_ERROR_INVALID_CONN_HANDLE) || (err_code == NRF_ERROR_INVALID_STATE) || (err_code == NRF_ERROR_BUSY)) {
        /* These errors can be expected when trying to send a Service Changed indication */
        /* if the CCCD is not set to indicate. Thus, set the returning error code to success. */
        OK_LOG_WARN_NOFLUSH("Client did not have the Service Changed indication set to enabled."
                            "Error: 0x%08x",
                            err_code);
        err_code = NRF_SUCCESS;
    }
    APP_ERROR_CHECK(err_code);
}

static void ok_peer_manager_evt_handler(pm_evt_t const *p_evt)
{
    ret_code_t err_code;
    uint8_t    data_len    = 0;
    uint8_t    bak_buff[2] = {0};

    switch (p_evt->evt_id) {

        case PM_EVT_BONDED_PEER_CONNECTED:
            OK_LOG_INFO_NOFLUSH("---> PM_EVT_BONDED_PEER_CONNECTED");
            request_service_changed = true;
            break;

        case PM_EVT_CONN_SEC_CONFIG_REQ:
            OK_LOG_INFO_NOFLUSH("---> PM_EVT_CONN_SEC_CONFIG_REQ");
            pm_conn_sec_config_t conn_sec_config = {.allow_repairing = true};
            pm_conn_sec_config_reply(p_evt->conn_handle, &conn_sec_config);
            break;

        case PM_EVT_CONN_SEC_SUCCEEDED:
            OK_LOG_INFO_NOFLUSH("---> PM_EVT_CONN_SEC_SUCCEEDED");

            pm_conn_sec_status_t conn_sec_status;

            // Check if the link is authenticated (meaning at least MITM).
            err_code = pm_conn_sec_status_get(p_evt->conn_handle, &conn_sec_status);
            APP_ERROR_CHECK(err_code);

            if (conn_sec_status.mitm_protected) {
                bak_buff[0] = OK_DOWNLINK_MAIN_CMD_BLE_PAIR_STATUS;
                bak_buff[1] = OK_DOWNLINK_SUB_CMD_BLE_PAIR_SUCCESS;
                data_len    = 2;

                OK_LOG_INFO_NOFLUSH("Link secured. Role: %d. conn_handle: %d, Procedure: %d", ble_conn_state_role(p_evt->conn_handle),
                                    p_evt->conn_handle, p_evt->params.conn_sec_succeeded.procedure);
            } else {
                // The peer did not use MITM protect.
                OK_LOG_INFO_NOFLUSH("Collector did not use MITM, disconnecting");
                err_code = pm_peer_id_get(p_evt->conn_handle, &m_peer_to_be_deleted);
                APP_ERROR_CHECK(err_code);
                err_code = sd_ble_gap_disconnect(p_evt->conn_handle, BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
                APP_ERROR_CHECK(err_code);
            }
            break;

        case PM_EVT_CONN_SEC_FAILED:
            OK_LOG_INFO_NOFLUSH("---> PM_EVT_CONN_SEC_FAILED");

            bak_buff[0] = OK_DOWNLINK_MAIN_CMD_BLE_PAIR_STATUS;
            bak_buff[1] = OK_DOWNLINK_SUB_CMD_BLE_PAIR_FAILED;
            data_len    = 2;
            break;

        case PM_EVT_LOCAL_DB_CACHE_APPLIED:
        case PM_EVT_LOCAL_DB_CACHE_APPLY_FAILED:
        case PM_EVT_PEER_DATA_UPDATE_SUCCEEDED:
        case PM_EVT_PEER_DATA_UPDATE_FAILED:
        case PM_EVT_PEER_DELETE_SUCCEEDED:
        case PM_EVT_PEER_DELETE_FAILED:
        case PM_EVT_PEERS_DELETE_FAILED:
            OK_LOG_INFO_NOFLUSH("pm_evt_handler evt_id %d", p_evt->evt_id);
            break;
        case PM_EVT_PEERS_DELETE_SUCCEEDED:
            ok_ble_adv_ctrl(0);
            OK_LOG_INFO_NOFLUSH("pm_evt_handler evt_id %d", p_evt->evt_id);
            break;

        default:
            OK_LOG_INFO_NOFLUSH("ok----> pm evt_id %d", p_evt->evt_id);
            break;
    }

    if (data_len > 0) {
        app_sched_event_put(bak_buff, data_len, ok_send_stm_data);
    }
}

/**@brief Function for handling Peer Manager events.
 *
 * @param[in] p_evt  Peer Manager event.
 */
static void pm_evt_handler(const pm_evt_t *p_evt)
{
    pm_handler_on_pm_evt(p_evt);
    pm_handler_disconnect_on_sec_failure(p_evt);
    pm_handler_flash_clean(p_evt);

    ok_peer_manager_evt_handler(p_evt);
}

void ok_peer_manager_lesc_process(void)
{
    uint32_t err_code;

    // ble adv stop, just return
    if (!ok_ble_adv_onoff_get()) {
        return;
    }

    if (!bond_check_key_flag) {
        err_code = nrf_ble_lesc_request_handler();
        APP_ERROR_CHECK(err_code);
    }
}

void ok_peer_manager_ble_evt_handler(const ble_evt_t *p_ble_evt)
{
    uint32_t err_code;
    uint8_t  bak_buff[8] = {0};
    uint16_t data_len    = 0;

    switch (p_ble_evt->header.evt_id) {
        case BLE_GAP_EVT_CONNECTED: {
            bak_buff[0] = OK_DOWNLINK_MAIN_CMD_BLE_STATUS;
            bak_buff[1] = OK_DOWNLINK_SUB_CMD_BLE_CONNECTED;
            data_len    = 2;

            m_peer_to_be_deleted = PM_PEER_ID_INVALID;
        } break;

        case BLE_GAP_EVT_DISCONNECTED: {
            bond_check_key_flag = 0;

            bak_buff[0] = OK_DOWNLINK_MAIN_CMD_BLE_STATUS;
            bak_buff[1] = OK_DOWNLINK_SUB_CMD_BLE_DISCONNECTED;
            data_len    = 2;

            if (m_peer_to_be_deleted != PM_PEER_ID_INVALID) {
                err_code = pm_peer_delete(m_peer_to_be_deleted);
                APP_ERROR_CHECK(err_code);
                OK_LOG_INFO_NOFLUSH("Collector's bond deleted");
                m_peer_to_be_deleted = PM_PEER_ID_INVALID;
            }

            request_service_changed = false;
        } break;

        case BLE_GAP_EVT_PASSKEY_DISPLAY: {
            OK_LOG_INFO_NOFLUSH("Gap evt passkey display.");

            char passkey[PASSKEY_LENGTH + 1] = {0};
            memcpy(passkey, p_ble_evt->evt.gap_evt.params.passkey_display.passkey, PASSKEY_LENGTH);
            passkey[PASSKEY_LENGTH] = 0;

            bak_buff[0] = OK_DOWNLINK_MAIN_CMD_BLE_PAIR_CODE;
            memcpy(&bak_buff[1], passkey, PASSKEY_LENGTH);
            data_len = PASSKEY_LENGTH + 1;

            OK_LOG_INFO_NOFLUSH("Passkey: %s", nrf_log_push(passkey));
        } break;

        case BLE_GAP_EVT_AUTH_STATUS: {
            OK_LOG_INFO_NOFLUSH("Gap evt auth status.");
            bond_check_key_flag = 1;
        } break;

        case BLE_GATTC_EVT_EXCHANGE_MTU_RSP: {
            OK_LOG_INFO_NOFLUSH("Gattc evt exchange mtu rsp.");
            if (request_service_changed) {
                request_service_changed = false;
                app_sched_event_put(NULL, 0, send_service_changed);
            }
        } break;

        default:
            break;
    }

    if (data_len > 0) {
        app_sched_event_put(bak_buff, data_len, ok_send_stm_data);
    }
}

bool ok_is_peer_manager_enable(void)
{
#ifdef BOND_ENABLE
    return true;
#else
    return false;
#endif
}

void ok_peer_manager_init(void)
{
    ble_gap_sec_params_t sec_param;
    ret_code_t           err_code;

    err_code = pm_init();
    APP_ERROR_CHECK(err_code);

    memset(&sec_param, 0, sizeof(ble_gap_sec_params_t));

    // Security parameters to be used for all security procedures.
    sec_param.bond           = SEC_PARAM_BOND;
    sec_param.mitm           = SEC_PARAM_MITM;
    sec_param.lesc           = SEC_PARAM_LESC;
    sec_param.keypress       = SEC_PARAM_KEYPRESS;
    sec_param.io_caps        = SEC_PARAM_IO_CAPABILITIES;
    sec_param.oob            = SEC_PARAM_OOB;
    sec_param.min_key_size   = SEC_PARAM_MIN_KEY_SIZE;
    sec_param.max_key_size   = SEC_PARAM_MAX_KEY_SIZE;
    sec_param.kdist_own.enc  = 1;
    sec_param.kdist_own.id   = 1;
    sec_param.kdist_peer.enc = 1;
    sec_param.kdist_peer.id  = 1;

    err_code = pm_sec_params_set(&sec_param);
    APP_ERROR_CHECK(err_code);
    
    err_code = pm_register(pm_evt_handler);
    APP_ERROR_CHECK(err_code);
}

void ok_peer_manage_update(void)
{
    ble_gap_sec_params_t sec_param;
    ret_code_t           err_code;

    memset(&sec_param, 0, sizeof(ble_gap_sec_params_t));

    // Security parameters to be used for all security procedures.
    sec_param.bond           = SEC_PARAM_BOND;
    sec_param.mitm           = SEC_PARAM_MITM;
    sec_param.lesc           = SEC_PARAM_LESC;
    sec_param.keypress       = SEC_PARAM_KEYPRESS;
    sec_param.io_caps        = SEC_PARAM_IO_CAPABILITIES;
    sec_param.oob            = SEC_PARAM_OOB;
    sec_param.min_key_size   = SEC_PARAM_MIN_KEY_SIZE;
    sec_param.max_key_size   = SEC_PARAM_MAX_KEY_SIZE;
    sec_param.kdist_own.enc  = 1;
    sec_param.kdist_own.id   = 1;
    sec_param.kdist_peer.enc = 1;
    sec_param.kdist_peer.id  = 1;

    err_code = pm_sec_params_set(&sec_param);
    APP_ERROR_CHECK(err_code);

    pm_register_slot0(pm_evt_handler);
}
