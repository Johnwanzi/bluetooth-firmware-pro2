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


#define FMNA_ADV_MODE_PIARING   0
#define FMNA_ADV_MODE_NEARBY    1
#define FMNA_ADV_MODE_SEPARATED 2

uint8_t mac_xro_data[5] = {0xc2, 0x87, 0x04, 0xa9, 0x63};

static uint8_t m_fmna_current_mode                       = 0;
static uint8_t m_fmna_adv[BLE_GAP_ADV_SET_DATA_SIZE_MAX] = {0};
static uint8_t m_fmna_scan_rsp[BLE_GAP_ADV_SET_DATA_SIZE_MAX] = {0};

void fmna_adv_platform_get_default_bt_addr(uint8_t default_bt_addr[FMNA_BLE_MAC_ADDR_BLEN])
{
    // Read hardcoded address from factory register
    memcpy(default_bt_addr, (uint8_t *)NRF_FICR->DEVICEADDR, FMNA_BLE_MAC_ADDR_BLEN);

    // Nordic SD sd_ble_gap_addr_set expects ble_gap_addr_t as LSB.
    reverse_array(default_bt_addr, 0, FMNA_BLE_MAC_ADDR_BLEN - 1);
}

void fmna_adv_platform_set_random_static_bt_addr(uint8_t new_bt_mac[FMNA_BLE_MAC_ADDR_BLEN])
{
    ble_gap_addr_t bd_addr;
    uint8_t default_bt_addr[FMNA_BLE_MAC_ADDR_BLEN];
    
    memcpy(default_bt_addr, (uint8_t *)NRF_FICR->DEVICEADDR, FMNA_BLE_MAC_ADDR_BLEN);
    
    // set address type bits for random static (0b11)
    default_bt_addr[5] |= (uint8_t)FMNA_ADV_ADDR_TYPE_MASK;
    
    memcpy(bd_addr.addr, new_bt_mac, FMNA_BLE_MAC_ADDR_BLEN);

    // Print the current public key 6 bytes Bluetooth Address
    NRF_LOG_INFO("BT MAC:");
    NRF_LOG_HEXDUMP_INFO(bd_addr.addr, 6);

    // Nordic SD sd_ble_gap_addr_set expects ble_gap_addr_t as LSB.
    reverse_array(bd_addr.addr, 0, FMNA_BLE_MAC_ADDR_BLEN - 1);

    bd_addr.addr_type = BLE_GAP_ADDR_TYPE_RANDOM_STATIC;

    if (memcmp(bd_addr.addr, default_bt_addr, sizeof(bd_addr.addr)) == 0) {
        for (int i = 0; i < 5; i++) {
            bd_addr.addr[i] ^= mac_xro_data[i];
        }
    } 

    ble_adv_manage_update(BLE_MFI_ADV_E, BLE_MANAGE_UPDATE_MAC_ADDR, &bd_addr);
}

void fmna_adv_platform_start_fast_adv(void)
{
    ble_adv_instance_t pair_adv_data = {0};

    // Configure Advertising module params
    pair_adv_data.adv_params.properties.type = BLE_GAP_ADV_TYPE_CONNECTABLE_SCANNABLE_UNDIRECTED;
    pair_adv_data.adv_params.filter_policy   = BLE_GAP_ADV_FP_ANY;
    pair_adv_data.adv_params.primary_phy     = BLE_GAP_PHY_AUTO;

    if (m_fmna_current_mode == FMNA_ADV_MODE_PIARING) {
        pair_adv_data.adv_params.interval = fmna_pairing_adv_fast_intv;
        pair_adv_data.adv_params.duration = fmna_pairing_adv_fast_duration;
    } else if (m_fmna_current_mode == FMNA_ADV_MODE_NEARBY) {
        pair_adv_data.adv_params.interval = fmna_nearby_adv_fast_intv;
        pair_adv_data.adv_params.duration = fmna_nearby_adv_fast_duration;
    } else if (m_fmna_current_mode == FMNA_ADV_MODE_SEPARATED) {
        pair_adv_data.adv_params.interval = fmna_separated_adv_fast_intv;
        pair_adv_data.adv_params.duration = fmna_separated_adv_fast_duration;
    } else {
        return;
    }

    ble_adv_manage_update(BLE_MFI_ADV_E, BLE_MANAGE_UPDATE_ADV_PARAMS, &pair_adv_data.adv_params);
}

void fmna_adv_platform_start_slow_adv(void)
{
    ble_adv_instance_t pair_adv_data = {0};

    // Configure Advertising module params
    pair_adv_data.adv_params.properties.type = BLE_GAP_ADV_TYPE_CONNECTABLE_SCANNABLE_UNDIRECTED;
    pair_adv_data.adv_params.filter_policy   = BLE_GAP_ADV_FP_ANY;
    pair_adv_data.adv_params.primary_phy     = BLE_GAP_PHY_AUTO;

    if (m_fmna_current_mode == FMNA_ADV_MODE_PIARING) {
        pair_adv_data.adv_params.interval = fmna_pairing_adv_slow_intv;
        pair_adv_data.adv_params.duration = fmna_pairing_adv_slow_duration;
    } else if (m_fmna_current_mode == FMNA_ADV_MODE_NEARBY) {
        pair_adv_data.adv_params.interval = fmna_nearby_adv_intv;
        pair_adv_data.adv_params.duration = fmna_nearby_adv_duration;
    } else if (m_fmna_current_mode == FMNA_ADV_MODE_SEPARATED) {
        pair_adv_data.adv_params.interval = fmna_separated_adv_slow_intv;
        pair_adv_data.adv_params.duration = fmna_separated_adv_slow_duration;
    } else {
        return;
    }

    ble_adv_manage_update(BLE_MFI_ADV_E, BLE_MANAGE_UPDATE_ADV_PARAMS, &pair_adv_data.adv_params);
}

void fmna_adv_platform_stop_adv(void)
{
    // sd_ble_gap_adv_stop(m_advertising.adv_handle);
}

static void fmna_adv_update_scan_rsp_data(ble_adv_instance_t *pair_adv_data)
{
    uint8_t off            = 0;
    uint8_t tmp_len        = strlen(FMNA_ADV_NAME);

    m_fmna_scan_rsp[off++] = tmp_len + 1;
    m_fmna_scan_rsp[off++] = BLE_GAP_AD_TYPE_COMPLETE_LOCAL_NAME;
    memcpy(&m_fmna_scan_rsp[off], FMNA_ADV_NAME, tmp_len);
    off += tmp_len;

    pair_adv_data->adv_data.scan_rsp_data.p_data = &m_fmna_scan_rsp[0];
    pair_adv_data->adv_data.scan_rsp_data.len    = off;
}

void fmna_adv_platform_init_pairing(uint8_t *pairing_adv_service_data, size_t pairing_adv_service_data_size)
{
    uint8_t            off           = 0;
    ble_adv_instance_t pair_adv_data = {0};

    NRF_LOG_INFO("ADV Pairing");

    memset(m_fmna_adv, 0x00, sizeof(m_fmna_adv));
    memset(m_fmna_scan_rsp, 0x00, sizeof(m_fmna_scan_rsp));

    // config adv data
    // complete list of 16-bit UUID
    m_fmna_adv[off++]             = 3;
    m_fmna_adv[off++]             = BLE_GAP_AD_TYPE_16BIT_SERVICE_UUID_COMPLETE;
    *(uint16_t *)&m_fmna_adv[off] = FINDMY_UUID_SERVICE;
    off += 2;

    // add service data
    m_fmna_adv[off++]             = pairing_adv_service_data_size + 2 + 1;
    m_fmna_adv[off++]             = BLE_GAP_AD_TYPE_SERVICE_DATA;
    *(uint16_t *)&m_fmna_adv[off] = FINDMY_UUID_SERVICE;
    off += 2;
    memcpy(&m_fmna_adv[off], pairing_adv_service_data, pairing_adv_service_data_size);
    off += pairing_adv_service_data_size;

    pair_adv_data.adv_data.adv_data.p_data = &m_fmna_adv[0];
    pair_adv_data.adv_data.adv_data.len    = off;

    fmna_adv_update_scan_rsp_data(&pair_adv_data);

    // Configure Advertising module params
    pair_adv_data.adv_params.properties.type = BLE_GAP_ADV_TYPE_CONNECTABLE_SCANNABLE_UNDIRECTED;
    pair_adv_data.adv_params.interval        = fmna_pairing_adv_fast_intv;
    pair_adv_data.adv_params.duration        = fmna_pairing_adv_fast_duration;
    pair_adv_data.adv_params.filter_policy   = BLE_GAP_ADV_FP_ANY;
    pair_adv_data.adv_params.primary_phy     = BLE_GAP_PHY_AUTO;

    m_fmna_current_mode = FMNA_ADV_MODE_PIARING;

    ble_adv_manage_update(BLE_MFI_ADV_E, BLE_MANAGE_UPDATE_ADV_TOTAL, &pair_adv_data);
}

void fmna_adv_platform_init_nearby(uint8_t *nearby_adv_manuf_data, size_t nearby_adv_manuf_data_size)
{
    uint8_t            off           = 0;
    ble_adv_instance_t pair_adv_data = {0};

    NRF_LOG_INFO("ADV Nearby");

    memset(m_fmna_adv, 0x00, sizeof(m_fmna_adv));

    // config adv data
    // menufacturer specific data
    m_fmna_adv[off++]             = 3 + nearby_adv_manuf_data_size;
    m_fmna_adv[off++]             = BLE_GAP_AD_TYPE_MANUFACTURER_SPECIFIC_DATA;
    *(uint16_t *)&m_fmna_adv[off] = FMNA_COMPANY_IDENTIFIER;
    off += 2;
    memcpy(&m_fmna_adv[off], nearby_adv_manuf_data, nearby_adv_manuf_data_size);
    off += nearby_adv_manuf_data_size;

    pair_adv_data.adv_data.adv_data.p_data = &m_fmna_adv[0];
    pair_adv_data.adv_data.adv_data.len    = off;

    fmna_adv_update_scan_rsp_data(&pair_adv_data);

    // Configure Advertising module params
    pair_adv_data.adv_params.properties.type = BLE_GAP_ADV_TYPE_CONNECTABLE_SCANNABLE_UNDIRECTED;
    pair_adv_data.adv_params.interval        = fmna_nearby_adv_fast_intv;
    pair_adv_data.adv_params.duration        = fmna_nearby_adv_fast_duration;
    pair_adv_data.adv_params.filter_policy   = BLE_GAP_ADV_FP_ANY;
    pair_adv_data.adv_params.primary_phy     = BLE_GAP_PHY_AUTO;

    m_fmna_current_mode = FMNA_ADV_MODE_NEARBY;

    ble_adv_manage_update(BLE_MFI_ADV_E, BLE_MANAGE_UPDATE_ADV_TOTAL, &pair_adv_data);
}

void fmna_adv_platform_init_separated(uint8_t *separated_adv_manuf_data, size_t separated_adv_manuf_data_size)
{
    uint8_t            off           = 0;
    ble_adv_instance_t pair_adv_data = {0};

    NRF_LOG_INFO("ADV Sepatated");

    memset(m_fmna_adv, 0x00, sizeof(m_fmna_adv));

    // config adv data
    // menufacturer specific data
    m_fmna_adv[off++]             = 3 + separated_adv_manuf_data_size;
    m_fmna_adv[off++]             = BLE_GAP_AD_TYPE_MANUFACTURER_SPECIFIC_DATA;
    *(uint16_t *)&m_fmna_adv[off] = FMNA_COMPANY_IDENTIFIER;
    off += 2;
    memcpy(&m_fmna_adv[off], separated_adv_manuf_data, separated_adv_manuf_data_size);
    off += separated_adv_manuf_data_size;

    pair_adv_data.adv_data.adv_data.p_data = &m_fmna_adv[0];
    pair_adv_data.adv_data.adv_data.len    = off;

    fmna_adv_update_scan_rsp_data(&pair_adv_data);

    // Configure Advertising module params
    pair_adv_data.adv_params.properties.type = BLE_GAP_ADV_TYPE_CONNECTABLE_SCANNABLE_UNDIRECTED;
    pair_adv_data.adv_params.interval        = fmna_separated_adv_fast_intv;
    pair_adv_data.adv_params.duration        = fmna_separated_adv_fast_duration;
    pair_adv_data.adv_params.filter_policy   = BLE_GAP_ADV_FP_ANY;
    pair_adv_data.adv_params.primary_phy     = BLE_GAP_PHY_AUTO;

    m_fmna_current_mode = FMNA_ADV_MODE_SEPARATED;

    ble_adv_manage_update(BLE_MFI_ADV_E, BLE_MANAGE_UPDATE_ADV_TOTAL, &pair_adv_data);
}
