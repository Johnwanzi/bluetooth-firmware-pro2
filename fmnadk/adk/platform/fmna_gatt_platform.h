/*
 *      Copyright (C) 2020 Apple Inc. All Rights Reserved.
 *
 *      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
 *      which is contained in the License.txt file distributed with the Find My Network ADK,
 *      and only to those who accept that license.
 */

#ifndef fmna_gatt_platform_h
#define fmna_gatt_platform_h

#include "ble_srv_common.h"
#include "nrf_sdh_ble.h"
#include "fmna_gatt.h"

#include "fmna_constants.h"

#define OPCODE_LENGTH 1
#define HANDLE_LENGTH 2

/** Maximum length of data (in bytes) that can be transmitted by the peer to the Nordic device. */
#if defined(NRF_SDH_BLE_GATT_MAX_MTU_SIZE) && (NRF_SDH_BLE_GATT_MAX_MTU_SIZE != 0)
    #define FMNA_GATT_MAX_DATA_LEN (NRF_SDH_BLE_GATT_MAX_MTU_SIZE - OPCODE_LENGTH - HANDLE_LENGTH)
#else
    #define FMNA_GATT_MAX_DATA_LEN (NRF_SDH_BLE_GATT_MAX_MTU_SIZE - OPCODE_LENGTH - HANDLE_LENGTH)
     #warning NRF_SDH_BLE_GATT_MAX_MTU_SIZE is not defined.
#endif

#define APP_CONFIG_DEF(_name)                                                                         \
static app_config_t _name;                                                                            \
NRF_SDH_BLE_OBSERVER(_name ## _obs,                                                                 \
                     APP_CONFIG_BLE_OBSERVER_PRIO,                                                    \
                     app_config_on_ble_evt, &_name)

/// Forward declaration of the app adv types.
typedef struct app_config_s             app_config_t;
typedef struct app_config_adv_s         app_config_adv_t;

extern app_config_t * p_m_config;

/// App config GATT write handler.
typedef void (*fmna_gatt_platform_write_handler_t) (uint16_t conn_handle, ble_gatts_evt_write_t const * p_evt_write);

/// App Config Service init structure. This contains all options and data needed for initialization of the service.
typedef struct {
    security_req_t                        app_config_rd_sec;                       /**< Security requirement for reading AppConfig characteristic value. */
    security_req_t                        app_config_wr_sec;                       /**< Security requirement for writing AppConfig characteristic value. */
    security_req_t                        app_config_cccd_wr_sec;
    fmna_gatt_platform_write_handler_t    write_handler;                           /**< Write handler for GATT characteristic write. */
} app_config_init_t;

/// App Config Service structure. This contains various status information for the service.
struct app_config_s {
    uint8_t                             uuid_type;                                 /** index for VS UUID */
    uint8_t                             uuid_type2;
    uint16_t                            conn_handle;                               /**< Handle of the most recent connection, used for pairing, UT play sound,
                                                                                  and non-encrypted disconnection. */
    fmna_gatt_platform_write_handler_t   write_handler;                             /**< Write handler for GATT characteristic write. */

    uint16_t                            findmy_service_handle;                      /**Find My Network Service Handle*/
    //Defined struct elements ble_gatts_char_handles_t for each characteristic for the Find My service.
    ble_gatts_char_handles_t            pairing_handle;                             /** Struct element for Pairing Characteristic of the Find My Network Service. */
    ble_gatts_char_handles_t            config_handle;                              /** Struct element for Config Characteristic of the Find My Network Service. */
    ble_gatts_char_handles_t            nonown_handle;                              /** Struct element for NonOwner Characteristic of the Find My Network Service. */
    ble_gatts_char_handles_t            paired_own_handle;                          /** Struct element for Paired owner Information Characteristic of the Find My Network Service. */
#ifdef DEBUG
    ble_gatts_char_handles_t            debug_handle;                               /** Struct element for Debug Characteristic of the Find My Network Service. */
#endif //DEBUG
    
    uint16_t                            uarp_service_handle;                        /**UARP Service Handle*/
    ble_gatts_char_handles_t            uarp_data_handle;                           /**UARP Data Control Point Characteristic Handle*/
    
    uint16_t                            ais_service_handle;                         /**Accessory Info Service Handle*/
    //Defined struct elements ble_gatts_char_handles_t for each characteristic for the Accessory Info service.
    ble_gatts_char_handles_t            prod_data_handle;
    ble_gatts_char_handles_t            manu_name_handle;
    ble_gatts_char_handles_t            model_name_handle;
    ble_gatts_char_handles_t            reserved_handle;
    ble_gatts_char_handles_t            acc_cat_handle;
    ble_gatts_char_handles_t            acc_cap_handle;
    ble_gatts_char_handles_t            fw_vers_handle;
    ble_gatts_char_handles_t            findmy_vers_handle;
    ble_gatts_char_handles_t            batt_type_handle;
    ble_gatts_char_handles_t            batt_lvl_handle;
    
};

/// Function for initializing the device info service.
ret_code_t device_info_service_init();

/// Function for initializing the App Config Service.
/// @param p_config  App Config Service structure. This structure will have to
///                 be supplied by the application. It will be initialized by this function,
///                 and will later be used to identify this particular service instance.
/// @param p_config_init Infor mation needed to initialize the service.
uint32_t app_config_init(app_config_t * p_config, const app_config_init_t * p_config_init);

/// Function for handling the Application's BLE Stack events.
/// @param p_ble_evt Event received from the BLE stack.
/// @param p_context App Config Service structure.
void app_config_on_ble_evt(ble_evt_t const * p_ble_evt, void * p_context);

/// Function for setting up up characteristics in the Find My Network service.
/// @param p_config App Config Service structure. This structure will have to
///                 be supplied by the application. It will be initialized by this function,
///                 and will later be used to identify this particular service instance.
/// @param p_config_init Information needed to initialize the service.
void findmy_service_setup(app_config_t * p_config, const app_config_init_t * p_config_init);

void fmna_gatt_platform_init(void);
void fmna_gatt_platform_services_init(void);

void fmna_gatt_platform_send_authorized_write_reply(bool accept);

uint16_t fmna_gatt_platform_get_most_recent_conn_handle(void);

ret_code_t fmna_gatt_platform_send_indication(uint16_t conn_handle, FMNA_Service_Opcode_t *opcode, uint8_t *data, uint16_t length);

uint8_t fmna_gatt_platform_send_indication_busy(uint16_t conn_handle, FMNA_Service_Opcode_t opcode, void *data, uint16_t length);
void fmna_gatt_platform_reset_indication_queue(void);
uint8_t fmna_gatt_platform_get_next_command_response_index(void);
void fmna_gatt_platform_send_next_indication(void);

#endif /* fmna_gatt_platform_h */
