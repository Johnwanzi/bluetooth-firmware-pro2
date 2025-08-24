/*
 *      Copyright (C) 2020 Apple Inc. All Rights Reserved.
 *
 *      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
 *      which is contained in the License.txt file distributed with the Find My Network ADK,
 *      and only to those who accept that license.
 */

#ifndef fmna_config_h
#define fmna_config_h

// #define DEBUG 1

#define BLE_ADVERTISING_ENABLED 1
#define PEER_MANAGER_ENABLED 1
#define PM_CENTRAL_ENABLED 0
#define NRFX_RNG_ENABLED 1
#define RNG_ENABLED 1
#define HARDFAULT_HANDLER_ENABLED 1
#define NRF_QUEUE_ENABLED 1
#define NRF_SDH_BLE_GAP_DATA_LENGTH 251
#define NRF_SDH_BLE_GATT_MAX_MTU_SIZE 247
#define NRF_SDH_BLE_GATTS_ATTR_TAB_SIZE 3500
#define NRF_STACK_GUARD_ENABLED 1
#define APP_CONFIG_BLE_OBSERVER_PRIO 2
#define FDS_ENABLED 1
#define NRF_FSTORAGE_ENABLED 1
#define PM_LOG_ENABLED 0
#define NRF_LOG_MSGPOOL_ELEMENT_SIZE 40
#define NRF_LOG_MSGPOOL_ELEMENT_COUNT 16
#define NRF_SDH_BLE_PERIPHERAL_LINK_COUNT 2
#define NRF_SDH_BLE_CENTRAL_LINK_COUNT 0
#define NRF_SDH_BLE_TOTAL_LINK_COUNT 2
#define PWR_MGMT_SLEEP_IN_CRITICAL_SECTION_REQUIRED 1
#define APP_TIMER_CONFIG_RTC_FREQUENCY 7
#define APP_TIMER_KEEPS_RTC_ACTIVE 1
#define APP_TIMER_V2_RTC1_ENABLED 1
#define APP_TIMER_SAFE_WINDOW_MS 10000
#define BLE_TPS_ENABLED 1
#define NRF_SDH_BLE_VS_UUID_COUNT 22

#endif /* fmna_config_h */
