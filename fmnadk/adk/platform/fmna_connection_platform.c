/*
 *      Copyright (C) 2020 Apple Inc. All Rights Reserved.
 *
 *      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
 *      which is contained in the License.txt file distributed with the Find My Network ADK,
 *      and only to those who accept that license.
 */

#include "fmna_connection_platform.h"

#include "fmna_constants.h"
#include "fmna_connection.h"
#include "fmna_gatt_platform.h"
#include "fmna_state_machine.h"
#include "fmna_peer_manager.h"
#include "security_dispatcher.h"
#include "nrf_log_ctrl.h"
#include "nrf_fstorage.h"
#include "nrf_fstorage_sd.h"
#include "id_manager.h"
#include "security_dispatcher.h"
#include "security_manager.h"
#include "gatt_cache_manager.h"
#include "fmna_storage.h"

ret_code_t fmna_connection_platform_disconnect(uint16_t conn_handle) {
    return sd_ble_gap_disconnect(conn_handle, BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
}

void fmna_connection_platform_gap_params_init(void) {
    ret_code_t              ret_code;
    ble_gap_conn_sec_mode_t sec_mode;
    
    // Setup the GAP connection parameters struct with the relevant values.
    ble_gap_conn_params_t   gap_conn_params = {
        .min_conn_interval = DEFAULT_MIN_CONNECTION_INTERVAL,
        .max_conn_interval = MAX_CONNECTION_INTERVAL,
        .slave_latency     = SLAVE_LATENCY,
        .conn_sup_timeout  = SUPERVISION_TIMEOUT,
    };
    
    BLE_GAP_CONN_SEC_MODE_SET_ENC_NO_MITM(&sec_mode);
    
    ret_code = sd_ble_gap_device_name_set(&sec_mode,
                                          (const uint8_t *)DEVICE_NAME,
                                          strlen(DEVICE_NAME));
    APP_ERROR_CHECK(ret_code);
    
    ret_code = sd_ble_gap_ppcp_set(&gap_conn_params);
    APP_ERROR_CHECK(ret_code);
}

/// Function for handling a Connection Parameters error.
/// @param nrf_error Error code containing information about what went wrong.
static void conn_params_error_handler(uint32_t nrf_error) {
    APP_ERROR_HANDLER(nrf_error);
}

void fmna_connection_platform_conn_params_init(void) {
    ret_code_t             ret_code;
    ble_conn_params_init_t cp_init = {0};
    
    cp_init.p_conn_params                  = NULL;
    cp_init.first_conn_params_update_delay = FIRST_CONN_PARAMS_UPDATE_DELAY;
    cp_init.next_conn_params_update_delay  = NEXT_CONN_PARAMS_UPDATE_DELAY;
    cp_init.max_conn_params_update_count   = MAX_CONN_PARAMS_UPDATE_COUNT;
    cp_init.start_on_notify_cccd_handle    = BLE_CONN_HANDLE_INVALID; // Start upon connection.
    cp_init.disconnect_on_fail             = true;
    cp_init.evt_handler                    = NULL;  // Ignore events.
    cp_init.error_handler                  = conn_params_error_handler;
    
    ret_code = ble_conn_params_init(&cp_init);
    APP_ERROR_CHECK(ret_code);
}

/// Handle encryption request for Find My Network accessories.
///
/// @details    This function bypasses Peer Manager handling. It is heavily based on
///             sec_info_request_process function from security_dispatcher.c.
static void fmna_sec_info_request_process(ble_gap_evt_t const * p_gap_evt) {
    ret_code_t                 err_code;
    ble_gap_enc_info_t         new_enc_info = {0};

    NRF_LOG_INFO("fmna_sec_info_request_process");
    NRF_LOG_INFO("Using FMNA LTK");

    // Copy over our own LTK
    memcpy(new_enc_info.ltk, fmna_connection_get_active_ltk(), BLE_GAP_SEC_KEY_LEN);
    new_enc_info.ltk_len = BLE_GAP_SEC_KEY_LEN;

    err_code = sd_ble_gap_sec_info_reply(p_gap_evt->conn_handle, &new_enc_info, NULL, NULL);
    if (err_code == NRF_ERROR_INVALID_STATE) {
        // Do nothing. If disconnecting, it will be caught later by the handling of the DISCONNECTED
        // event. If there is no SEC_INFO_REQ pending, there is either a logic error, or the user
        // is also calling sd_ble_gap_sec_info_reply(), but there is no way for the present code to
        // detect which one is the case.
        NRF_LOG_WARNING("sd_ble_gap_sec_info_reply() returned NRF_EROR_INVALID_STATE, which is an"\
                        "error unless the link is disconnecting.");
    } else if (err_code != NRF_SUCCESS) {
        NRF_LOG_ERROR("Could not complete encryption procedure. sd_ble_gap_sec_info_reply() "\
                      "returned %s. conn_handle: %d.",
                      nrf_strerror_get(err_code),
                      p_gap_evt->conn_handle);
    }
}


void fmna_ble_peripheral_evt(ble_evt_t const * p_ble_evt) {
    ble_gap_evt_t const * p_gap_evt = &p_ble_evt->evt.gap_evt;
    
    switch (p_ble_evt->header.evt_id) {
        case BLE_GAP_EVT_CONNECTED:
            peer_peer_manage_update();
            fmna_connection_connected_handler(p_gap_evt->conn_handle, p_gap_evt->params.connected.conn_params.min_conn_interval);
            break;
        
        case BLE_GAP_EVT_CONN_PARAM_UPDATE:
            fmna_connection_conn_param_update_handler(p_gap_evt->conn_handle, p_gap_evt->params.connected.conn_params.min_conn_interval);
            break;
            
        case BLE_GAP_EVT_DISCONNECTED:
            fmna_connection_disconnected_handler(p_gap_evt->conn_handle, p_gap_evt->params.disconnected.reason);
            break;
        
        case BLE_GAP_EVT_PHY_UPDATE_REQUEST: {
            ble_gap_phys_t const phys = {
                .rx_phys = BLE_GAP_PHY_AUTO,
                .tx_phys = BLE_GAP_PHY_AUTO,
            };
            
            // sd_ble_gap_phy_update should be best effort
            ret_code_t ret_code = sd_ble_gap_phy_update(p_gap_evt->conn_handle, &phys);
            if (NRF_SUCCESS != ret_code) {
                NRF_LOG_ERROR("PHY update err %d", ret_code);
            }
        } break;
            

        case BLE_GAP_EVT_CONN_SEC_UPDATE:
            if (fmna_connection_is_fmna_paired()) {
                NRF_LOG_INFO("FMNA BLE_GAP_EVT_CONN_SEC_UPDATE");

                NRF_LOG_INFO("Conn secured: conn_handle: 0x%x, level: %d.",
                            p_ble_evt->evt.gap_evt.conn_handle,
                            p_ble_evt->evt.gap_evt.params.conn_sec_update.conn_sec.sec_mode.lv);

                // mark as encrypted in the connection record
                fmna_connection_update_connection_info(p_gap_evt->conn_handle,
                                                       FMNA_MULTI_STATUS_ENCRYPTED,
                                                       true);

                // BT pairing completed successfully/ link was encrypted. Send BONDED event to state machine.
                fmna_evt_handler(FMNA_SM_EVENT_BONDED, NULL);
            }
            break;

        case BLE_GAP_EVT_SEC_INFO_REQUEST:
            if (fmna_connection_is_fmna_paired()) {
                NRF_LOG_INFO("FMNA BLE_GAP_EVT_SEC_INFO_REQUEST");

                fmna_sec_info_request_process(p_gap_evt);
            }
            break;
            
        case BLE_GAP_EVT_SEC_PARAMS_REQUEST: {
            NRF_LOG_INFO("FMNA BLE_GAP_EVT_SEC_PARAMS_REQUEST");
            
            if (fmna_connection_is_fmna_paired()) {
                // Reject the incoming security request if we are already FMNA paired.
                NRF_LOG_ERROR("FMNA Already paired. Reject request.");
                
                ret_code_t ret_code = sd_ble_gap_sec_params_reply(p_gap_evt->conn_handle, BLE_GAP_SEC_STATUS_PAIRING_NOT_SUPP, NULL, NULL);
                if (NRF_SUCCESS != ret_code) {
                    NRF_LOG_ERROR("sd_ble_gap_sec_params_reply err 0x%x", ret_code);
                }
            }
            
        } break;
            
        default:
            // no implementation needed
            break;
    }
}

void fmna_connection_platform_log_token_help(void * auth_token, uint16_t token_size, void * auth_uuid, uint16_t uuid_size) {
    NRF_LOG_INFO("MFi token: 0x%x, %d UUID 0x%x, %d", auth_token, token_size, auth_uuid, uuid_size );
    NRF_LOG_INFO("UUID: nrfjprog -f nrf52 --memrd 0x%x --w 8 --n %d", auth_uuid, uuid_size);
    NRF_LOG_INFO("Token: nrfjprog -f nrf52 --memrd 0x%x --w 8 --n %d", auth_token, token_size);
    while (NRF_LOG_PROCESS()){}
}

#define MFI_TOKEN_MAX_LOG_CHUNK 64
void fmna_connection_platform_log_token(void * auth_token, uint16_t token_size, uint8_t isCrash) {
    uint16_t token_remaining = token_size;
    void * p_temp = auth_token;
    uint16_t to_print;
    
    NRF_LOG_INFO("MFi Token:");
    while (token_remaining) {
        if (token_remaining > MFI_TOKEN_MAX_LOG_CHUNK) {
            to_print = MFI_TOKEN_MAX_LOG_CHUNK;
        }
        else {
            to_print = token_remaining;
        }
        NRF_LOG_HEXDUMP_INFO(p_temp, to_print);
        token_remaining -= to_print;
        p_temp += to_print;
        if (isCrash) {
            while (NRF_LOG_PROCESS()){}
        }
    }
}

char num_to_char(uint8_t nibble) {
    if (nibble < 10) {
        return (('0' + nibble));
    }
    
    return (('a' + nibble - 10));
}

void fmna_connection_platform_get_serial_number(uint8_t * pSN, uint8_t length) {
    uint8_t temp[8];
    uint16_t remaining = length;
    int i=0;
    
    // xor device id and bd addr to identify the device
    *((uint32_t *)temp) =  NRF_FICR->DEVICEID[0];
    *((uint32_t *)temp) ^= NRF_FICR->DEVICEADDR[0];
    
    *((uint32_t *)(temp + 4)) =  NRF_FICR->DEVICEID[1];
    *((uint32_t *)(temp + 4)) ^= NRF_FICR->DEVICEADDR[1];
    
    // Convert to a character string
    for (; i<8 && remaining; ++i) {
        pSN[2*i] = num_to_char((temp[i] & 0x0f));
        remaining--;
        if (remaining) {
            pSN[2*i + 1] = num_to_char(((temp[i]>>4) & 0x0f));
            remaining--;
        }
    }
    
    // Pad remaining with 'f'
    if (remaining) {
        pSN[i] = 'f';
        remaining--;
        i++;
    }
    NRF_LOG_INFO("Serial Number:");
    NRF_LOG_HEXDUMP_INFO(pSN, length);
}

bool m_new_token_stored = false;

void fmna_connection_update_mfi_token_storage(void *p_data, uint16_t data_size) {
    NRF_LOG_INFO("Update MFi Token / UUID");
    fmna_storage_write(FMNA_AUTH_TOKEN_UUID, p_data, data_size);
    m_new_token_stored = true;
    fmna_state_machine_dispatch_event(FMNA_SM_EVENT_FMNA_PAIRING_MFITOKEN);
}

bool fmna_connection_mfi_token_stored(void) {
    return m_new_token_stored;
}
