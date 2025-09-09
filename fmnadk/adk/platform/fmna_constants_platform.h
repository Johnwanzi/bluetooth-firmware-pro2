/*
 *      Copyright (C) 2020 Apple Inc. All Rights Reserved.
 *
 *      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
 *      which is contained in the License.txt file distributed with the Find My Network ADK,
 *      and only to those who accept that license.
 */

#ifndef fmna_constants_platform_h
#define fmna_constants_platform_h

#define FMNA_MANUFACTURER_NAME                  "Onekey"
#define FMNA_MODEL_NAME                         "OneKey Pro 2"
#define FMNA_PID                                0xCAFE
#define FMNA_HARDWARE_VERSION                   "1"
#define FMNA_HARDWARE_VERSION                   "1"
#define FMNA_ADV_NAME                           "Test-FindMy"

#define FMNA_LOG_ERROR(...)                     NRF_LOG_ERROR(__VA_ARGS__)
#define FMNA_LOG_WARNING(...)                   NRF_LOG_WARNING( __VA_ARGS__)
#define FMNA_LOG_INFO(...)                      NRF_LOG_INFO( __VA_ARGS__)
#define FMNA_LOG_DEBUG(...)                     NRF_LOG_DEBUG( __VA_ARGS__)

#define FMNA_LOG_HEXDUMP_INFO(p_data, len)      NRF_LOG_HEXDUMP_INFO(p_data, len)
#define FMNA_LOG_HEXDUMP_DEBUG(p_data, len)     NRF_LOG_HEXDUMP_DEBUG(p_data, len)

#define MAX_SUPPORTED_CONNECTIONS               NRF_SDH_BLE_PERIPHERAL_LINK_COUNT
#define GATT_MAX_MTU_SIZE                       NRF_SDH_BLE_GATT_MAX_MTU_SIZE

#define CONN_HANDLE_INVALID                     BLE_CONN_HANDLE_INVALID
#define CONN_HANDLE_ALL                         BLE_CONN_HANDLE_ALL
#define GAP_SEC_KEY_LEN                         BLE_GAP_SEC_KEY_LEN

#define FMNA_SUCCESS                            NRF_SUCCESS               ///< Successful command
#define FMNA_ERROR_INTERNAL                     NRF_ERROR_INTERNAL        ///< Internal Error
#define FMNA_ERROR_INVALID_STATE                NRF_ERROR_INVALID_STATE   ///< Invalid state, operation disallowed in this state
#define FMNA_ERROR_INVALID_LENGTH               NRF_ERROR_INVALID_LENGTH  ///< Invalid Length
#define FMNA_ERROR_INVALID_DATA                 NRF_ERROR_INVALID_DATA    ///< Invalid Data
#define FMNA_ERROR_NULL                         NRF_ERROR_NULL            ///< Null Pointer

#define FMNA_ERROR_CHECK(ERR_CODE)              APP_ERROR_CHECK(ERR_CODE)

// Macro for calling error handler function if supplied boolean value is false.
#define FMNA_ERROR_CHECK_BOOL(ERR_CODE)         APP_ERROR_CHECK_BOOL(ERR_CODE)

#define MSEC_TO_TIMER_TICKS                     APP_TIMER_TICKS

//MARK: Nordic SDK required macros.
#define SEC_PARAM_BOND                          0                         /**< Perform bonding. */
#define SEC_PARAM_MITM                          0                         /**< Man In The Middle protection not required. */
#define SEC_PARAM_LESC                          0                         /**< LE Secure Connections not enabled. */
#define SEC_PARAM_KEYPRESS                      0                         /**< Keypress notifications not enabled. */
#define SEC_PARAM_IO_CAPABILITIES               BLE_GAP_IO_CAPS_NONE      /**< No I/O capabilities. */
#define SEC_PARAM_OOB                           0                         /**< Out Of Band data not available. */
#define SEC_PARAM_MIN_KEY_SIZE                  7                         /**< Minimum encryption key size in octets. */
#define SEC_PARAM_MAX_KEY_SIZE                  16                        /**< Maximum encryption key size in octets. */

/** Priority of the application BLE event handler. */
#define FMNA_BLE_CONN_CFG_TAG                    1                         /**< A tag identifying the SoftDevice BLE configuration. */
#define FMNA_BLE_OBSERVER_PRIO                   3

#define fmna_ret_code_t                         ret_code_t

#define ADV_TYPE_SERVICE_DATA                   BLE_GAP_AD_TYPE_SERVICE_DATA                      

#endif /* fmna_constants_platform_h */
