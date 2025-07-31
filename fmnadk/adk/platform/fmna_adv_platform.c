/*
 *      Copyright (C) 2020 Apple Inc. All Rights Reserved.
 *
 *      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
 *      which is contained in the License.txt file distributed with the Find My Network ADK,
 *      and only to those who accept that license.
 */

#include "fmna_gatt_platform.h"

#include "fmna_constants.h"
#include "fmna_util.h"
#include "fmna_adv.h"

BLE_ADVERTISING_DEF(m_advertising);                               /**< Advertising module instance. */

// Universally unique service identifier.
static ble_uuid_t m_prox_adv_uuids[] = {
    {FINDMY_UUID_SERVICE, BLE_UUID_TYPE_BLE}
};

void fmna_adv_platform_get_default_bt_addr(uint8_t default_bt_addr[FMNA_BLE_MAC_ADDR_BLEN]) {
    // Read hardcoded address from factory register
    memcpy(default_bt_addr, (uint8_t *)NRF_FICR->DEVICEADDR, FMNA_BLE_MAC_ADDR_BLEN);
    
    // Nordic SD sd_ble_gap_addr_set expects ble_gap_addr_t as LSB.
    reverse_array(default_bt_addr, 0, FMNA_BLE_MAC_ADDR_BLEN-1);
}

void fmna_adv_platform_set_random_static_bt_addr(uint8_t new_bt_mac[FMNA_BLE_MAC_ADDR_BLEN]) {
    ret_code_t ret_code;
    ble_gap_addr_t bd_addr;
    
    memcpy(bd_addr.addr, new_bt_mac, FMNA_BLE_MAC_ADDR_BLEN);
    
    // Print the current public key 6 bytes Bluetooth Address
    NRF_LOG_INFO("BT MAC:");
    NRF_LOG_HEXDUMP_INFO(bd_addr.addr, 6);
    
    // Nordic SD sd_ble_gap_addr_set expects ble_gap_addr_t as LSB.
    reverse_array(bd_addr.addr, 0, FMNA_BLE_MAC_ADDR_BLEN-1);
    
    bd_addr.addr_type = BLE_GAP_ADDR_TYPE_RANDOM_STATIC;
    
    ret_code = sd_ble_gap_addr_set(&bd_addr);
    APP_ERROR_CHECK(ret_code);
}

static void fmna_adv_start_adv(ble_adv_mode_t adv_mode) {
    ret_code_t ret_code = ble_advertising_start(&m_advertising, adv_mode);
    
    if (ret_code != NRF_SUCCESS) {
        NRF_LOG_INFO("error in advertising 0x%x", ret_code);
    }
}

void fmna_adv_platform_start_fast_adv(void) {
    fmna_adv_start_adv(BLE_ADV_MODE_FAST);
}

void fmna_adv_platform_start_slow_adv(void) {
    fmna_adv_start_adv(BLE_ADV_MODE_SLOW);
}

void fmna_adv_platform_stop_adv(void) {
    sd_ble_gap_adv_stop(m_advertising.adv_handle);
}

void fmna_adv_platform_init_pairing(uint8_t *pairing_adv_service_data, size_t pairing_adv_service_data_size) {
    NRF_LOG_INFO("ADV Pairing");
    
    ret_code_t               ret_code;
    ble_advertising_init_t   init;
    ble_advdata_service_data_t service_data;
    
    memset(&init, 0, sizeof(init));
    
    service_data.service_uuid = FINDMY_UUID_SERVICE;
    service_data.data.p_data = pairing_adv_service_data;
    service_data.data.size = pairing_adv_service_data_size;

    init.advdata.name_type               = BLE_ADVDATA_NO_NAME;
    init.advdata.include_appearance      = false;
    init.advdata.service_data_count      = 1;
    init.advdata.p_service_data_array    = &service_data;
    init.advdata.uuids_complete.uuid_cnt = sizeof(m_prox_adv_uuids) / sizeof(m_prox_adv_uuids[0]);
    init.advdata.uuids_complete.p_uuids  = m_prox_adv_uuids;
    
    // Configure Advertising module params
    init.config.ble_adv_directed_interval          = fmna_pairing_adv_fast_intv;
    init.config.ble_adv_directed_timeout           = fmna_pairing_adv_fast_duration;
    init.config.ble_adv_fast_enabled               = true;
    init.config.ble_adv_fast_interval              = fmna_pairing_adv_fast_intv;
    init.config.ble_adv_fast_timeout               = fmna_pairing_adv_fast_duration;
    init.config.ble_adv_slow_enabled               = true;
    init.config.ble_adv_slow_interval              = fmna_pairing_adv_slow_intv;
    init.config.ble_adv_slow_timeout               = fmna_pairing_adv_slow_duration;
    init.config.ble_adv_on_disconnect_disabled     = true;
    
    ret_code = ble_advertising_init(&m_advertising, &init);
    APP_ERROR_CHECK(ret_code);
    
    ret_code = sd_ble_gap_tx_power_set(BLE_GAP_TX_POWER_ROLE_ADV, m_advertising.adv_handle, FMNA_ADV_TX_POWER_DBM);
    APP_ERROR_CHECK(ret_code);

    ble_advertising_conn_cfg_tag_set(&m_advertising, FMNA_BLE_CONN_CFG_TAG);
}

void fmna_adv_platform_init_nearby(uint8_t *nearby_adv_manuf_data, size_t nearby_adv_manuf_data_size) {
    ret_code_t               ret_code;
    ble_advertising_init_t   init;
    ble_advdata_manuf_data_t manuf_specific_data;

    memset(&init, 0, sizeof(init));

    manuf_specific_data.company_identifier = FMNA_COMPANY_IDENTIFIER;
    manuf_specific_data.data.p_data = nearby_adv_manuf_data;
    manuf_specific_data.data.size = nearby_adv_manuf_data_size;
   
    init.advdata.name_type               = BLE_ADVDATA_NO_NAME;
    init.advdata.include_appearance      = false;
    init.advdata.p_manuf_specific_data   = &manuf_specific_data;

    // Configure Advertising module params
    init.config.ble_adv_directed_interval          = fmna_nearby_adv_fast_intv;
    init.config.ble_adv_directed_timeout           = fmna_nearby_adv_fast_duration;
    init.config.ble_adv_fast_enabled               = true;
    init.config.ble_adv_fast_interval              = fmna_nearby_adv_fast_intv;
    init.config.ble_adv_fast_timeout               = fmna_nearby_adv_fast_duration;
    init.config.ble_adv_slow_enabled               = true;
    init.config.ble_adv_slow_interval              = fmna_nearby_adv_intv;
    init.config.ble_adv_slow_timeout               = fmna_nearby_adv_duration;
    init.config.ble_adv_on_disconnect_disabled     = true;
    
    ret_code = ble_advertising_init(&m_advertising, &init);
    APP_ERROR_CHECK(ret_code);
    
    ret_code = sd_ble_gap_tx_power_set(BLE_GAP_TX_POWER_ROLE_ADV, m_advertising.adv_handle, FMNA_ADV_TX_POWER_DBM);
    APP_ERROR_CHECK(ret_code);

    ble_advertising_conn_cfg_tag_set(&m_advertising, FMNA_BLE_CONN_CFG_TAG);
}


void fmna_adv_platform_init_separated(uint8_t *separated_adv_manuf_data, size_t separated_adv_manuf_data_size) {
    ret_code_t               ret_code;
    ble_advertising_init_t   init;
    ble_advdata_manuf_data_t manuf_specific_data;
    
    memset(&init, 0, sizeof(init));

    manuf_specific_data.company_identifier = FMNA_COMPANY_IDENTIFIER;
    manuf_specific_data.data.p_data = separated_adv_manuf_data;
    manuf_specific_data.data.size = separated_adv_manuf_data_size;
    
    init.advdata.name_type               = BLE_ADVDATA_NO_NAME;
    init.advdata.include_appearance      = false;
    init.advdata.p_manuf_specific_data   = &manuf_specific_data;
    
    // Configure Advertising module params
    init.config.ble_adv_directed_interval          = fmna_separated_adv_fast_intv;
    init.config.ble_adv_directed_timeout           = fmna_separated_adv_fast_duration;
    init.config.ble_adv_fast_enabled               = true;
    init.config.ble_adv_fast_interval              = fmna_separated_adv_fast_intv;
    init.config.ble_adv_fast_timeout               = fmna_separated_adv_fast_duration;
    init.config.ble_adv_slow_enabled               = true;
    init.config.ble_adv_slow_interval              = fmna_separated_adv_slow_intv;
    init.config.ble_adv_slow_timeout               = fmna_separated_adv_slow_duration;
    init.config.ble_adv_on_disconnect_disabled     = true;
    
    ret_code = ble_advertising_init(&m_advertising, &init);
    APP_ERROR_CHECK(ret_code);
    
    ret_code = sd_ble_gap_tx_power_set(BLE_GAP_TX_POWER_ROLE_ADV, m_advertising.adv_handle, FMNA_ADV_TX_POWER_DBM);
    APP_ERROR_CHECK(ret_code);

    ble_advertising_conn_cfg_tag_set(&m_advertising, FMNA_BLE_CONN_CFG_TAG);
}
