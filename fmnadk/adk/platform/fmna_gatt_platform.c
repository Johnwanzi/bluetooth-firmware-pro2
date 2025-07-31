/*
 *      Copyright (C) 2020 Apple Inc. All Rights Reserved.
 *
 *      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
 *      which is contained in the License.txt file distributed with the Find My Network ADK,
 *      and only to those who accept that license.
 */

#include "fmna_gatt_platform.h"
#include "fmna_platform_includes.h"
#include "fmna_constants.h"
#include "fmna_gatt.h"
#include "fmna_version.h"
#include "fmna_state_machine.h"
#include "fmna_connection.h"
#include "fmna_config_control_point.h"
#include "fmna_util.h"
#include "app_util_platform.h"
#include "nrf_queue.h"
#include "ble_tps.h"
#include "fmna_adv_platform.h"

#ifdef USE_UARP
#include "fmna_uarp_control_point.h"
#endif

BLE_TPS_DEF(m_tps);

#define MAX_NUM_CHAR_WRITE_HANDLERS 6

NRF_BLE_GATT_DEF(m_gatt); /**< GATT module instance. */
APP_CONFIG_DEF(m_config); /**< App config module instance */
app_config_t * p_m_config = &m_config;

// very basic indication queue
#define FMNA_INDICATION_QUEUE_SIZE 15
typedef struct {
    void * data;
    uint16_t length;
    uint16_t conn_handle;
    FMNA_Service_Opcode_t opcode;
} fmna_indication_queue_t;

//m_indication_queue_busy is used to flag there is an active indication
// on going and new ones should be queued
static uint8_t m_indication_queue_busy = 0;
// m_indication_conn_handle holds the connection handle for the current indication
// If the there is a disconnect for this connection handle before the indication succeeds,
// then we should abandon and move on to the next queued indication
static uint16_t m_indication_conn_handle = BLE_CONN_HANDLE_INVALID;

NRF_QUEUE_DEF(fmna_indication_queue_t, m_indication_queue, FMNA_INDICATION_QUEUE_SIZE, NRF_QUEUE_MODE_OVERFLOW);


/**  GATT Characteristic Write Handler Type */
typedef fmna_ret_code_t (*fmna_gatt_platform_char_write_fptr_t) (uint16_t conn_handle, uint16_t uuid, uint16_t length, uint8_t const *data);

/** GATT Characteristic Write Handler Structure */
typedef struct {
    uint16_t                              value_handle;    // Written Characteristic Value Handle
    fmna_gatt_platform_char_write_fptr_t  handler;         // Event Handler
} fmna_gatt_platform_char_write_handler_t;

/** GATT Characteristic Write Handler List. */
static fmna_gatt_platform_char_write_handler_t m_char_write_handlers[MAX_NUM_CHAR_WRITE_HANDLERS];

void fmna_gatt_platform_write_handler(uint16_t conn_handle, ble_gatts_evt_write_t const * p_evt_write);

static ret_code_t fmna_gatt_platform_register_char_write_handler(uint16_t value_handle, fmna_gatt_platform_char_write_fptr_t handler);

void fmna_gatt_platform_init(void) {
    ret_code_t ret_code = nrf_ble_gatt_init(&m_gatt, NULL);
    APP_ERROR_CHECK(ret_code);
}

/// Function for handling the Connect event.
/// @param p_config App Config Service structure.
/// @param p_ble_evt Event received from the BLE stack.
static void on_connect(app_config_t * p_config, ble_evt_t const * p_ble_evt) {
    // The config handle servers as the most recently connected device.
    // This allows for easier commnuication with the device during:
    // Pairing lock
    // UT Play sound
    // connected / not encrypted devices
    p_config->conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
}

/// Function for handling the Disconnect event.
/// @param p_config App Config Service structure.
/// @param p_ble_evt Event received from the BLE stack.
static void on_disconnect(app_config_t * p_config, ble_evt_t const * p_ble_evt) {
    UNUSED_PARAMETER(p_ble_evt);
#ifdef USE_UARP
    fmna_uarp_disconnect(p_ble_evt->evt.gap_evt.conn_handle);
#endif
    if (p_ble_evt->evt.gap_evt.conn_handle == p_config->conn_handle) {
        p_config->conn_handle = BLE_CONN_HANDLE_INVALID;
    }
}

/// Function for handling the Write event.
/// @param p_config App Config Service structure.
/// @param p_ble_evt Event received from the BLE stack.
static void on_write(app_config_t * p_config, ble_evt_t const * p_ble_evt) {
    ble_gatts_evt_write_t const * p_evt_write = &p_ble_evt->evt.gatts_evt.params.write;
 
    uint16_t conn_handle = p_ble_evt->evt.gatts_evt.conn_handle;
    
    // If we have a valid connection and an implemented write handler.
    if (fmna_connection_is_valid_connection(conn_handle) &&
        p_config->write_handler) {
        p_config->write_handler(conn_handle, p_evt_write);
#ifdef USE_UARP
        if (p_evt_write->handle == p_m_config->uarp_data_handle.cccd_handle){
            fmna_uarp_connect(conn_handle);
        }
#endif
    }
}

void app_config_on_ble_evt(ble_evt_t const * p_ble_evt, void * p_context) {
    if ((p_context == NULL) || (p_ble_evt == NULL)) {
        return;
    }
    
    ret_code_t ret_code;
    uint16_t rx_client_mtu;
    app_config_t * p_config = (app_config_t *)p_context;

    switch (p_ble_evt->header.evt_id) {
        case BLE_GATTS_EVT_RW_AUTHORIZE_REQUEST: {
            ble_gatts_evt_rw_authorize_request_t const *p_auth_request = &(p_ble_evt->evt.gatts_evt.params.authorize_request);
            if (p_auth_request->type == BLE_GATTS_AUTHORIZE_TYPE_WRITE) {
                NRF_LOG_INFO("Authorized Write Request Received:");
                ble_gatts_evt_write_t const *p_evt_write = &(p_auth_request->request.write);
                fmna_gatt_platform_write_handler(p_ble_evt->evt.gatts_evt.conn_handle, p_evt_write);
            } else {
                NRF_LOG_ERROR("Unsupported authorized request type received: 0x%x", p_auth_request->type);
            }
        } break;

        case BLE_GAP_EVT_CONNECTED:
            on_connect(p_config, p_ble_evt);
            break;

        case BLE_GAP_EVT_DISCONNECTED:
            on_disconnect(p_config, p_ble_evt);
            if (p_ble_evt->evt.gap_evt.conn_handle == m_indication_conn_handle) {
                fmna_gatt_dispatch_send_next_packet();
            }
            break;

        case BLE_GATTS_EVT_WRITE:
            NRF_LOG_INFO("Write Command Received");
            on_write(p_config, p_ble_evt);
            break;

        case BLE_GATTS_EVT_HVC:
            NRF_LOG_INFO("iOS has successfully received an indication");
            m_indication_conn_handle = BLE_CONN_HANDLE_INVALID;
            if (memcmp_val(&fmna_service_current_extended_packet_tx, 0, sizeof(fmna_service_current_extended_packet_tx))) {
#ifdef USE_UARP
                if (p_ble_evt->evt.gatts_evt.params.hvc.handle == p_m_config->uarp_data_handle.value_handle) {
                    NRF_LOG_INFO("UARP Packet has finished being sent.");
                    fmna_uarp_packet_sent();
                }
                else
#endif
                {
                    NRF_LOG_INFO("Indication has finished being sent.");
                }
                
                fmna_gatt_dispatch_send_next_packet();
            } else {
                NRF_LOG_INFO("sending another indication");
                fmna_gatt_dispatch_send_packet_extension_indication();
            }
            break;
            
        case BLE_GATTS_EVT_EXCHANGE_MTU_REQUEST:
            rx_client_mtu = p_ble_evt->evt.gatts_evt.params.exchange_mtu_request.client_rx_mtu;
            
            NRF_LOG_INFO("GATT Client MTU: %d", rx_client_mtu);
            m_gatt_mtu = MIN(NRF_SDH_BLE_GATT_MAX_MTU_SIZE, rx_client_mtu) - GATT_HEADER_LEN;
            
            NRF_LOG_INFO("new GATT MTU: %d", m_gatt_mtu);
            break;
            
        case BLE_GATTS_EVT_TIMEOUT:
            // disconnect on GATT Server timeout event
            NRF_LOG_INFO("Gatts Timeout---------------");
            ret_code = sd_ble_gap_disconnect(p_ble_evt->evt.gatts_evt.conn_handle,
                                             BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
            APP_ERROR_CHECK(ret_code);
            break;
    
        default:
            break;
    }
}

void findmy_char_add(app_config_t * p_config, const app_config_init_t * p_config_init){
    ret_code_t ret_code;
    
    //Add the Find My Network characteristics
    ble_uuid128_t findmy_char_base_uuid128 = {FINDMY_CHAR_BASE_UUID};
    ret_code = sd_ble_uuid_vs_add(&findmy_char_base_uuid128, &p_config->uuid_type);
    NRF_LOG_DEBUG("VS UUID addition index: %d", p_config->uuid_type);
    APP_ERROR_CHECK(ret_code);

    // Add pairing characteristic
    ble_add_char_params_t add_pairing_char_params;
    memset(&add_pairing_char_params, 0, sizeof(add_pairing_char_params));

    add_pairing_char_params.uuid                = FINDMY_UUID_PAIRING_CHAR;
    add_pairing_char_params.uuid_type           = p_config->uuid_type;
    add_pairing_char_params.max_len             = m_gatt_mtu;
    add_pairing_char_params.init_len            = m_gatt_mtu;
    add_pairing_char_params.write_access        = p_config_init->app_config_wr_sec;
    add_pairing_char_params.read_access         = p_config_init->app_config_rd_sec;
    add_pairing_char_params.cccd_write_access   = p_config_init->app_config_cccd_wr_sec;
    add_pairing_char_params.char_props.indicate = 1;
    add_pairing_char_params.char_props.read     = 1;
    add_pairing_char_params.is_var_len          = 1;
    add_pairing_char_params.char_props.write    = 1;
    add_pairing_char_params.is_defered_write    = 1;
   
    NRF_LOG_INFO("Pairing Characteristic addition attempt");
    ret_code = characteristic_add(p_config->findmy_service_handle, &add_pairing_char_params, &(p_config->pairing_handle));
    APP_ERROR_CHECK(ret_code);
    
    ret_code = fmna_gatt_platform_register_char_write_handler(p_config->pairing_handle.value_handle, fmna_gatt_pairing_char_authorized_write_handler);
    APP_ERROR_CHECK(ret_code);

    // Add configuration characteristic
    ble_add_char_params_t add_config_char_params;
    memset(&add_config_char_params, 0, sizeof(add_config_char_params));
    add_config_char_params.uuid                 = FINDMY_UUID_CONFIG_CHAR;
    add_config_char_params.uuid_type            = p_config->uuid_type;
    add_config_char_params.max_len              = FMNA_GATT_MAX_DATA_LEN;
    add_config_char_params.init_len             = FMNA_GATT_MAX_DATA_LEN;
    add_config_char_params.read_access          = p_config_init->app_config_rd_sec;
    add_config_char_params.write_access         = p_config_init->app_config_wr_sec;
    add_config_char_params.cccd_write_access    = p_config_init->app_config_cccd_wr_sec;
    add_config_char_params.char_props.indicate  = 1;
    add_config_char_params.char_props.read      = 1;
    add_config_char_params.is_var_len           = 1;
    add_config_char_params.char_props.write     = 1;

    NRF_LOG_INFO("Configuration Characteristic addition attempt");
    ret_code = characteristic_add(p_config->findmy_service_handle, &add_config_char_params, &(p_config->config_handle));
    APP_ERROR_CHECK(ret_code);
    
    ret_code = fmna_gatt_platform_register_char_write_handler(p_config->config_handle.value_handle, fmna_gatt_config_char_write_handler);
    APP_ERROR_CHECK(ret_code);
    
    // Add Non-owner characteristic
    ble_add_char_params_t add_nonowner_char_params;
    memset(&add_nonowner_char_params, 0, sizeof(add_nonowner_char_params));
    add_nonowner_char_params.uuid                   = FINDMY_UUID_NONOWN_CHAR;
    add_nonowner_char_params.uuid_type              = p_config->uuid_type;
    add_nonowner_char_params.max_len                = NONOWN_MAX_LEN;
    add_nonowner_char_params.init_len               = NONOWN_MAX_LEN;
    add_nonowner_char_params.read_access            = SEC_OPEN;
    add_nonowner_char_params.write_access           = SEC_OPEN;
    add_nonowner_char_params.cccd_write_access      = SEC_OPEN;
    add_nonowner_char_params.char_props.indicate    = 1;
    add_nonowner_char_params.char_props.read        = 1;
    add_nonowner_char_params.is_var_len             = 1;
    add_nonowner_char_params.char_props.write       = 1;

    NRF_LOG_INFO("Non-Owner Characteristic addition attempt");
    ret_code = characteristic_add(p_config->findmy_service_handle, &add_nonowner_char_params, &(p_config->nonown_handle));
    APP_ERROR_CHECK(ret_code);
    
    ret_code = fmna_gatt_platform_register_char_write_handler(p_config->nonown_handle.value_handle, fmna_gatt_nonown_char_write_handler);
    APP_ERROR_CHECK(ret_code);
    
#ifdef DEBUG
    // Add Debug characteristic
    ble_add_char_params_t add_debug_char_params;
    memset(&add_debug_char_params, 0, sizeof(add_debug_char_params));
    add_debug_char_params.uuid                   = FINDMY_UUID_DEBUG_CHAR;
    add_debug_char_params.uuid_type              = p_config->uuid_type;
    add_debug_char_params.max_len                = FMNA_GATT_MAX_DATA_LEN;
    add_debug_char_params.init_len               = FMNA_GATT_MAX_DATA_LEN;
    add_debug_char_params.read_access            = SEC_OPEN;
    add_debug_char_params.write_access           = SEC_OPEN;
    add_debug_char_params.cccd_write_access      = SEC_OPEN;
    add_debug_char_params.char_props.indicate    = 1;
    add_debug_char_params.char_props.read        = 1;
    add_debug_char_params.is_var_len             = 1;
    add_debug_char_params.char_props.write       = 1;

    NRF_LOG_INFO("Debug Characteristic addition attempt");
    ret_code = characteristic_add(p_config->findmy_service_handle, &add_debug_char_params, &(p_config->debug_handle));
    APP_ERROR_CHECK(ret_code);
    
    ret_code = fmna_gatt_platform_register_char_write_handler(p_config->debug_handle.value_handle, fmna_gatt_debug_char_write_handler);
    APP_ERROR_CHECK(ret_code);
#endif // DEBUG
    
    // Add Paired Owner information characteristic
    ble_add_char_params_t app_paired_owner_char_params;
    memset(&app_paired_owner_char_params, 0, sizeof(app_paired_owner_char_params));
    app_paired_owner_char_params.uuid                   = FINDMY_UUID_PAIRED_OWNER_CHAR;
    app_paired_owner_char_params.uuid_type              = p_config->uuid_type;
    app_paired_owner_char_params.max_len                = PAIRED_OWNER_MAX_LEN;
    app_paired_owner_char_params.init_len               = PAIRED_OWNER_MAX_LEN;
    app_paired_owner_char_params.read_access            = SEC_OPEN;
    app_paired_owner_char_params.write_access           = SEC_OPEN;
    app_paired_owner_char_params.cccd_write_access      = SEC_OPEN;
    app_paired_owner_char_params.char_props.indicate    = 1;
    app_paired_owner_char_params.char_props.read        = 1;
    app_paired_owner_char_params.is_var_len             = 1;
    app_paired_owner_char_params.char_props.write       = 1;

    NRF_LOG_INFO("Paired Owner Characteristic addition attempt");
    ret_code = characteristic_add(p_config->findmy_service_handle, &app_paired_owner_char_params, &(p_config->paired_own_handle));
    APP_ERROR_CHECK(ret_code);
    
    ret_code = fmna_gatt_platform_register_char_write_handler(p_config->paired_own_handle.value_handle, fmna_gatt_paired_owner_char_write_handler);
    APP_ERROR_CHECK(ret_code);

}

#ifdef USE_UARP
void uarp_char_add(app_config_t * p_config, const app_config_init_t * p_config_init){
    ret_code_t ret_code;
    
    //Add the UARP characteristics
    ble_uuid128_t uarp_char_base_uuid128 = {UARP_CHAR_BASE_UUID};
    ret_code = sd_ble_uuid_vs_add(&uarp_char_base_uuid128, &p_config->uuid_type);
    NRF_LOG_DEBUG("VS UUID addition index: %d", p_config->uuid_type);
    APP_ERROR_CHECK(ret_code);

    // Add data characteristic
    ble_add_char_params_t data_char_params;
    memset(&data_char_params, 0, sizeof(data_char_params));

    data_char_params.uuid                = UARP_UUID_DATA_CHAR;
    data_char_params.uuid_type           = p_config->uuid_type;
    data_char_params.max_len             = m_gatt_mtu;
    data_char_params.init_len            = m_gatt_mtu;
    data_char_params.write_access        = p_config_init->app_config_wr_sec;
    data_char_params.read_access         = p_config_init->app_config_rd_sec;
    data_char_params.cccd_write_access   = p_config_init->app_config_cccd_wr_sec;
    data_char_params.char_props.indicate = 1;
    data_char_params.char_props.read     = 1;
    data_char_params.is_var_len          = 1;
    data_char_params.char_props.write    = 1;
    data_char_params.is_defered_write    = 1;
   
    NRF_LOG_INFO("UARP Data Characteristic addition attempt");
    ret_code = characteristic_add(p_config->uarp_service_handle, &data_char_params, &(p_config->uarp_data_handle));
    APP_ERROR_CHECK(ret_code);
    
    ret_code = fmna_gatt_platform_register_char_write_handler(p_config->uarp_data_handle.value_handle, fmna_gatt_uarp_char_write_handler);
    APP_ERROR_CHECK(ret_code);
}
#endif

void init_ais_characteristics(app_config_t * p_config) {
    ret_code_t ret_code;
    ble_gatts_value_t gatts_value;
    gatts_value.offset = 0;
    
    uint8_t product_data[PRODUCT_DATA_BLEN] = PRODUCT_DATA_VAL;
    gatts_value.len = PRODUCT_DATA_BLEN;
    gatts_value.p_value = (uint8_t *)(product_data);
    ret_code = sd_ble_gatts_value_set(p_m_config->conn_handle, p_m_config->prod_data_handle.value_handle, &gatts_value);
    APP_ERROR_CHECK(ret_code);
    
    uint8_t manu_name[MANU_NAME_MAX_LEN] = FMNA_MANUFACTURER_NAME;
    gatts_value.len = MANU_NAME_MAX_LEN;
    gatts_value.p_value = (uint8_t *)(manu_name);
    ret_code = sd_ble_gatts_value_set(p_m_config->conn_handle, p_m_config->manu_name_handle.value_handle, &gatts_value);
    APP_ERROR_CHECK(ret_code);
    
    uint8_t model_name[MODEL_NAME_MAX_LEN] = FMNA_MODEL_NAME;
    gatts_value.len = MODEL_NAME_MAX_LEN;
    gatts_value.p_value = (uint8_t *)(model_name);
    ret_code = sd_ble_gatts_value_set(p_m_config->conn_handle, p_m_config->model_name_handle.value_handle, &gatts_value);
    APP_ERROR_CHECK(ret_code);
    
    uint8_t accessory_category[ACC_CATEGORY_MAX_LEN];
    memset(accessory_category, ACCESSORY_CATEGORY, sizeof(uint8_t));
    gatts_value.len = ACC_CATEGORY_MAX_LEN;
    gatts_value.p_value = (uint8_t *)(accessory_category);
    ret_code = sd_ble_gatts_value_set(p_m_config->conn_handle, p_m_config->acc_cat_handle.value_handle, &gatts_value);
    APP_ERROR_CHECK(ret_code);
    
    uint32_t acc_capability = 0;
    // Accessory capabilities bitmask as defined in Find My Network specification.
    // ADK supports play sound (via nrf52 DK LEDs), Firmware update service, and serial number lookup by BLE.
    // No motion detection or NFC capabilities.
    SET_BIT(acc_capability, ACC_CAPABILITY_PLAY_SOUND_BIT_POS);
    SET_BIT(acc_capability, ACC_CAPABILITY_SRNM_LOOKUP_BLE_BIT_POS);
    SET_BIT(acc_capability, ACC_CAPABILITY_FW_UPDATE_SERVICE_BIT_POS);
    gatts_value.len = ACC_CAP_MAX_LEN;
    gatts_value.p_value = (uint8_t *)&acc_capability;
    ret_code = sd_ble_gatts_value_set(p_m_config->conn_handle, p_m_config->acc_cap_handle.value_handle, &gatts_value);
    APP_ERROR_CHECK(ret_code);
    
    uint32_t fw_vers = fmna_version_get_fw_version();
    gatts_value.len = FW_VERS_MAX_LEN;
    gatts_value.p_value = (uint8_t *)(&fw_vers);
    ret_code = sd_ble_gatts_value_set(p_m_config->conn_handle, p_m_config->fw_vers_handle.value_handle, &gatts_value);
    APP_ERROR_CHECK(ret_code);
    
    uint32_t findmy_vers = 0x00010000; // FindMy version 1.0.0
    gatts_value.len = FINDMY_VERS_MAX_LEN;
    gatts_value.p_value = (uint8_t *)(&findmy_vers);
    ret_code = sd_ble_gatts_value_set(p_m_config->conn_handle, p_m_config->findmy_vers_handle.value_handle, &gatts_value);
    APP_ERROR_CHECK(ret_code);
    
    uint8_t batt_type = 0; // Powered
    gatts_value.len = BATT_TYPE_MAX_LEN;
    gatts_value.p_value = (uint8_t *)(&batt_type);
    ret_code = sd_ble_gatts_value_set(p_m_config->conn_handle, p_m_config->batt_type_handle.value_handle, &gatts_value);
    APP_ERROR_CHECK(ret_code);
    
    uint8_t batt_state = 0; // Full battery state
    gatts_value.len = BATT_LVL_MAX_LEN;
    gatts_value.p_value = (uint8_t *)(&batt_state);
    ret_code = sd_ble_gatts_value_set(p_m_config->conn_handle, p_m_config->batt_lvl_handle.value_handle, &gatts_value);
    APP_ERROR_CHECK(ret_code);
    
}

ret_code_t ais_characteristic_add(app_config_t * p_config, const app_config_init_t * p_config_init, uint16_t char_uuid, uint16_t char_len, ble_gatts_char_handles_t * char_handle) {
    ret_code_t ret_code;
    ble_add_char_params_t ais_char_to_add_params;
    memset(&ais_char_to_add_params, 0, sizeof(ais_char_to_add_params));
    ais_char_to_add_params.uuid                 = char_uuid;
    ais_char_to_add_params.uuid_type            = p_config->uuid_type2;
    ais_char_to_add_params.init_len             = char_len;
    ais_char_to_add_params.max_len              = char_len;
    ais_char_to_add_params.read_access          = SEC_OPEN;
    ais_char_to_add_params.write_access         = SEC_NO_ACCESS;
    ais_char_to_add_params.cccd_write_access    = SEC_NO_ACCESS;
    ais_char_to_add_params.char_props.read      = 1;
    ret_code = characteristic_add(p_config->ais_service_handle, &ais_char_to_add_params, char_handle);
    return ret_code;
}

void ais_add_all_char(app_config_t * p_config, const app_config_init_t * p_config_init) {
    ret_code_t ret_code;
    
    // Add the Accessory Info Service characteristics
    ble_uuid128_t ais_char_base_uuid128 = {AIS_CHAR_BASE_UUID};
    ret_code = sd_ble_uuid_vs_add(&ais_char_base_uuid128, &p_config->uuid_type2);
    APP_ERROR_CHECK(ret_code);
    
    NRF_LOG_DEBUG("Adding product data characteristic");
    ret_code = ais_characteristic_add(p_config, p_config_init, FMNA_AIS_UUID_PRODUCT_DATA, PROD_DATA_MAX_LEN, &(p_config->prod_data_handle));
    APP_ERROR_CHECK(ret_code);
    NRF_LOG_DEBUG("Adding manufacturer name characteristic");
    ret_code = ais_characteristic_add(p_config, p_config_init, FMNA_AIS_UUID_MANU_NAME, MANU_NAME_MAX_LEN, &(p_config->manu_name_handle));
    APP_ERROR_CHECK(ret_code);
    NRF_LOG_DEBUG("Adding model name characteristic");
    ret_code = ais_characteristic_add(p_config, p_config_init, FMNA_AIS_UUID_MODEL_NAME, MODEL_NAME_MAX_LEN, &(p_config->model_name_handle));
    APP_ERROR_CHECK(ret_code);
    NRF_LOG_DEBUG("Adding accessory category characteristic");
    ret_code = ais_characteristic_add(p_config, p_config_init, FMNA_AIS_UUID_ACC_CATEGORY, ACC_CATEGORY_MAX_LEN, &(p_config->acc_cat_handle));
    APP_ERROR_CHECK(ret_code);
    NRF_LOG_DEBUG("Adding accessory capabilities characteristic");
    ret_code = ais_characteristic_add(p_config, p_config_init, FMNA_AIS_UUID_ACC_CAPABILITIES, ACC_CAP_MAX_LEN, &(p_config->acc_cap_handle));
    APP_ERROR_CHECK(ret_code);
    NRF_LOG_DEBUG("Adding firmware version characteristic");
    ret_code = ais_characteristic_add(p_config, p_config_init, FMNA_AIS_UUID_FW_VERS, FW_VERS_MAX_LEN, &(p_config->fw_vers_handle));
    APP_ERROR_CHECK(ret_code);
    NRF_LOG_DEBUG("Adding findmy version characteristic");
    ret_code = ais_characteristic_add(p_config, p_config_init, FMNA_AIS_UUID_FINDMY_VERS, FINDMY_VERS_MAX_LEN, &(p_config->findmy_vers_handle));
    APP_ERROR_CHECK(ret_code);
    NRF_LOG_DEBUG("Adding battery level characteristic");
    ret_code = ais_characteristic_add(p_config, p_config_init, FMNA_AIS_UUID_BATT_LVL, BATT_LVL_MAX_LEN, &(p_config->batt_lvl_handle));
    APP_ERROR_CHECK(ret_code);
    NRF_LOG_DEBUG("Adding battery type characteristic");
    ret_code = ais_characteristic_add(p_config, p_config_init, FMNA_AIS_UUID_BATT_TYPE, BATT_TYPE_MAX_LEN, &(p_config->batt_type_handle));
    APP_ERROR_CHECK(ret_code);
}

void findmy_service_add(app_config_t * p_config, const app_config_init_t * p_config_init) {
    ret_code_t ret_code;
    
    ble_uuid_t findmy_uuid = {
        .uuid = FINDMY_UUID_SERVICE,
        .type = BLE_UUID_TYPE_BLE,
    };

    // adds service to attribute table
    ret_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY, &findmy_uuid, &(p_config->findmy_service_handle));
    APP_ERROR_CHECK(ret_code);
    NRF_LOG_DEBUG("Successfully added Find My Service");
    
    findmy_char_add(p_config, p_config_init);
}

#ifdef USE_UARP
void uarp_service_add(app_config_t * p_config, const app_config_init_t * p_config_init) {
    ret_code_t ret_code;
    
    ble_uuid_t uarp_uuid = {
        .uuid = UARP_UUID_SERVICE,
        .type = BLE_UUID_TYPE_BLE,
    };

    // adds service to attribute table
    ret_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY, &uarp_uuid, &(p_config->findmy_service_handle));
    APP_ERROR_CHECK(ret_code);
    NRF_LOG_DEBUG("Successfully added UARP Service");
    
    uarp_char_add(p_config, p_config_init);
}
#endif

void ais_service_add(app_config_t * p_config, const app_config_init_t * p_config_init) {
    // Add Accessory Info Service
    ble_uuid_t ais_uuid;
    ret_code_t ret_code;
    NRF_LOG_DEBUG("AIS UUID addition attempt");
    
    ble_uuid128_t ais_service_base_uuid128 = {AIS_SERVICE_BASE_UUID};
    ret_code = sd_ble_uuid_vs_add(&ais_service_base_uuid128, &p_config->uuid_type);
    NRF_LOG_DEBUG("VS UUID addition index: %d", p_config->uuid_type);

    APP_ERROR_CHECK(ret_code);
    ais_uuid.uuid = FMNA_AIS_UUID_SERVICE;
    
    ais_uuid.type = p_config->uuid_type;
    ret_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY, &ais_uuid, &(p_config->ais_service_handle));
    APP_ERROR_CHECK(ret_code);
    NRF_LOG_DEBUG("Successfully added Accessory Info Service");
    
    // Call the function that will add all of the characteristics
    ais_add_all_char(p_config, p_config_init);
    NRF_LOG_INFO("Successfully added Accessory Info Service and Characteristics");
    init_ais_characteristics(p_config);
}

uint32_t app_config_init(app_config_t * p_config, const app_config_init_t * p_config_init) {
    // need err code
    if (p_config == NULL || p_config_init == NULL) {
        return NRF_ERROR_NULL;
    }

    // Initialize service structure
    p_config->write_handler = p_config_init->write_handler;
    p_config->conn_handle = BLE_CONN_HANDLE_INVALID;

    findmy_service_add(p_config, p_config_init);

#ifdef USE_UARP
    uarp_service_add(p_config, p_config_init);
#endif
    
    ais_service_add(p_config, p_config_init);

    NRF_LOG_DEBUG("\nApp config app_config_init - success!!!");

    return NRF_SUCCESS;
}

ret_code_t fmna_gatt_platform_register_char_write_handler(uint16_t value_handle, fmna_gatt_platform_char_write_fptr_t handler) {
    for (uint8_t i = 0; i < MAX_NUM_CHAR_WRITE_HANDLERS; i++) {
        if (!m_char_write_handlers[i].handler) {
            m_char_write_handlers[i].value_handle = value_handle;
            m_char_write_handlers[i].handler = handler;
            return NRF_SUCCESS;
        }
    }
    
    NRF_LOG_ERROR("Couldn't register write handler. Please increase handler array size.");
    return NRF_ERROR_NO_MEM;
}

void fmna_gatt_platform_write_handler(uint16_t conn_handle, ble_gatts_evt_write_t const * p_evt_write) {
    NRF_LOG_INFO("Charac. Write UUID: 0x%x ", p_evt_write->uuid.uuid);
    ret_code_t ret_code;
    
    for (uint8_t i = 0; i < MAX_NUM_CHAR_WRITE_HANDLERS; i++) {
        if (m_char_write_handlers[i].handler && (m_char_write_handlers[i].value_handle == p_evt_write->handle)) {
            ret_code = m_char_write_handlers[i].handler(conn_handle, p_evt_write->uuid.uuid, p_evt_write->len, p_evt_write->data);
            if (ret_code != NRF_SUCCESS) {
                NRF_LOG_ERROR("fmna_gatt_platform_write_handler error %d", ret_code);
            }
            break;
        }
    }
}

void fmna_gatt_platform_services_init(void) {
    ret_code_t         ret_code;
    app_config_init_t  config_init;
    ble_tps_init_t     tps_init = {0};
    
    // Init the app config services
    memset(&config_init, 0, sizeof(config_init));
    
    config_init.write_handler            = fmna_gatt_platform_write_handler;
    config_init.app_config_rd_sec        = SEC_JUST_WORKS; 
    config_init.app_config_wr_sec        = SEC_JUST_WORKS;
    config_init.app_config_cccd_wr_sec   = SEC_JUST_WORKS;
    ret_code = app_config_init(&m_config, &config_init);
    APP_ERROR_CHECK(ret_code);
    
    tps_init.initial_tx_power_level = FMNA_ADV_TX_POWER_DBM;
    tps_init.tpl_rd_sec = SEC_OPEN;
    ret_code = ble_tps_init(&m_tps, &tps_init);
    APP_ERROR_CHECK(ret_code);
}

void fmna_gatt_platform_send_authorized_write_reply(bool accept) {
    if (fmna_connection_get_num_connections() == 0) {
        return;
    }
    
    ret_code_t ret_code;
    ble_gatts_rw_authorize_reply_params_t auth_reply;
    memset(&auth_reply, 0, sizeof(ble_gatts_rw_authorize_reply_params_t));
    auth_reply.type =   BLE_GATTS_AUTHORIZE_TYPE_WRITE;
    auth_reply.params.write.update = 1;
    if (accept) {
        auth_reply.params.write.gatt_status = BLE_GATT_STATUS_SUCCESS;
    } else {
        auth_reply.params.write.gatt_status = BLE_GATT_STATUS_ATTERR_WRITE_NOT_PERMITTED;
    }
    ret_code = sd_ble_gatts_rw_authorize_reply(p_m_config->conn_handle, &auth_reply);
    if (ret_code != NRF_SUCCESS) {
        NRF_LOG_ERROR("fmna_gatt_platform_send_authorized_write_reply: sd_ble_gatts_rw_authorize_reply failed with error %d", ret_code);
    }
}

uint16_t fmna_gatt_platform_get_most_recent_conn_handle(void) {
    return p_m_config->conn_handle;
}

ret_code_t fmna_gatt_platform_send_indication(uint16_t conn_handle, FMNA_Service_Opcode_t *p_opcode, uint8_t *data, uint16_t length) {
    // Init SDK indication parameters
    ble_gatts_hvx_params_t  ind_hvx_params;
    memset(&ind_hvx_params, 0, sizeof(ind_hvx_params));
    ind_hvx_params.type   = BLE_GATT_HVX_INDICATION;
    ind_hvx_params.p_data = data;
    ind_hvx_params.p_len  = &length;

    m_indication_conn_handle = conn_handle;
    
    // If indication needs to be fragmented
    if (*p_opcode == FMNA_SERVICE_OPCODE_PACKET_EXTENSION) {
        *p_opcode = fmna_service_current_extended_packet_tx.opcode;
    }
    
    switch (*p_opcode & FMNA_SERVICE_OPCODE_BASE_MASK) {
        case FMNA_SERVICE_OPCODE_PAIRING_CONTROL_POINT_BASE:
            ind_hvx_params.handle = p_m_config->pairing_handle.value_handle;
            break;
            
        case FMNA_SERVICE_OPCODE_CONFIG_CONTROL_POINT_BASE:
            ind_hvx_params.handle = p_m_config->config_handle.value_handle;
            break;
        
        case FMNA_SERVICE_OPCODE_NON_OWNER_CONTROL_POINT_BASE:
            ind_hvx_params.handle = p_m_config->nonown_handle.value_handle;
            break;
            
        case FMNA_SERVICE_OPCODE_PAIRED_OWNER_CONTROL_POINT_BASE:
            ind_hvx_params.handle = p_m_config->paired_own_handle.value_handle;
            break;
            
#if DEBUG
        case FMNA_SERVICE_OPCODE_DEBUG_CONTROL_POINT_BASE:
            ind_hvx_params.handle = p_m_config->debug_handle.value_handle;
            break;
#endif // DEBUG
       
#ifdef USE_UARP
        case FMNA_SERVICE_OPCODE_INTERNAL_UARP_BASE:
            ind_hvx_params.handle = p_m_config->uarp_data_handle.value_handle;
            break;
#endif
            
        default:
            NRF_LOG_ERROR("Unknown opcode: 0x%x", *p_opcode);
            break;
    }
        
    return sd_ble_gatts_hvx(conn_handle, &ind_hvx_params);
    
}

uint8_t fmna_gatt_platform_send_indication_busy(uint16_t conn_handle, FMNA_Service_Opcode_t opcode, void *data, uint16_t length) {
    uint8_t queue_msg = 1;
    CRITICAL_REGION_ENTER();
    if (m_indication_queue_busy == 0) {
        queue_msg = 0;
        m_indication_queue_busy = 1;
    }
    else {
        fmna_indication_queue_t q_data = {
            .data = data,
            .length = length,
            .conn_handle = conn_handle,
            .opcode = opcode,
        };
        nrf_queue_push(&m_indication_queue, &q_data);
        FMNA_LOG_INFO("TX indication queued");
    }
    CRITICAL_REGION_EXIT();

    return queue_msg;
}

void fmna_gatt_platform_reset_indication_queue(void) {
    CRITICAL_REGION_ENTER();
    m_indication_queue_busy = 0;
    m_indication_conn_handle = BLE_CONN_HANDLE_INVALID;
    nrf_queue_reset(&m_indication_queue);
    CRITICAL_REGION_EXIT();
}

uint8_t fmna_gatt_platform_get_next_command_response_index(void) {
    uint8_t index;
    CRITICAL_REGION_ENTER();
    index = m_command_response_index;
    m_command_response_index++;
    if (m_command_response_index <= MAX_CONTROL_POINT_RSP) {
        m_command_response_index = 0;
    }
    CRITICAL_REGION_EXIT();
    return index;
}

void fmna_gatt_platform_send_next_indication(void) {
    // Check the queue
    FMNA_LOG_INFO("fmna_gatt_platform_send_next_indication");
    if (nrf_queue_is_empty(&m_indication_queue)) {
        // free up the busy flag
        CRITICAL_REGION_ENTER();
        m_indication_queue_busy = 0;
        m_indication_conn_handle = BLE_CONN_HANDLE_INVALID;
        CRITICAL_REGION_EXIT();
    }
    else {
        fmna_indication_queue_t entry;
        nrf_queue_pop (&m_indication_queue, &entry);
        fmna_gatt_send_indication_internal(entry.conn_handle, entry.opcode, entry.data, entry.length);
    }
}
