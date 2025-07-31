

/*
*      Copyright (C) 2020 Apple Inc. All Rights Reserved.
*
*      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
*      which is contained in the License.txt file distributed with the Find My Network ADK,
*      and only to those who accept that license.
*/


#include "fmna_platform_includes.h"
#include "fmna_debug_control_point.h"
#include "fmna_gatt.h"
#include "fmna_state_machine.h"
#include "fmna_crypto.h"
#include "fmna_connection.h"
#include "fmna_adv.h"
#include "fmna_motion_detection.h"

#ifdef DEBUG

//MARK: RX Packet Definitions

typedef struct {
    FMNA_Service_Opcode_t set_key_rotation_timeout_opcode;
    uint32_t              timeout_ms;
} __attribute__((packed)) set_key_rotation_timeout_packet_t;

typedef struct {
    FMNA_Service_Opcode_t ut_motion_timers_config_opcode;
    uint32_t              separated_ut_timeout_seconds;
    uint32_t              separated_ut_backoff_timeout_seconds;
} __attribute__((packed)) ut_motion_timers_config_packet_t;

static uint8_t m_log_chunk[GATT_MAX_MTU_SIZE];

/// RX Length Check managers for default and variable length cases.
static fmna_service_length_check_manager_t rx_length_check_managers[] = \
{
    /* RX Opcode                                             Data Length */
    { FMNA_SERVICE_DEBUG_OPCODE_SET_KEY_ROTATION_TIMEOUT,    sizeof(set_key_rotation_timeout_packet_t)  },
    { FMNA_SERVICE_DEBUG_OPCODE_RESET,                       sizeof(generic_control_point_packet_t)     },
    { FMNA_SERVICE_DEBUG_OPCODE_RETRIEVE_LOGS,               sizeof(generic_control_point_packet_t)     },
    { FMNA_SERVICE_DEBUG_UT_MOTION_TIMERS_CONFIG,            sizeof(ut_motion_timers_config_packet_t)   },
};

static FMNA_Response_Status_t rx_error_check(FMNA_Service_Opcode_t opcode, uint8_t const * data, uint16_t length) {
    return fmna_gatt_verify_control_point_opcode_and_length(opcode, length, rx_length_check_managers, FMNA_SERVICE_LENGTH_CHECK_MANAGERS_SIZE(rx_length_check_managers));
}

void fmna_debug_control_point_rx_handler(uint16_t conn_handle, uint8_t const * data, uint16_t length) {
    FMNA_Service_Opcode_t opcode = *(FMNA_Service_Opcode_t *)data;
    
    FMNA_Response_Status_t response_status = rx_error_check(opcode, data, length);
    
    if (response_status != RESPONSE_STATUS_SUCCESS) {
        FMNA_LOG_ERROR("Rx error 0x%x for opcode 0x%x, conn_handle 0x%x", response_status, opcode, conn_handle);
        if (response_status == RESPONSE_STATUS_INVALID_COMMAND) {
            opcode = FMNA_SERVICE_OPCODE_NONE;
        }
        fmna_gatt_send_command_response(FMNA_SERVICE_DEBUG_OPCODE_COMMAND_RESPONSE, conn_handle, opcode, response_status);
        return;
    }
    
    response_status = RESPONSE_STATUS_NO_COMMAND_RESPONSE;
        
    FMNA_LOG_INFO("Debug CP rx: opcode = 0x%x, conn_handle 0x%x", opcode, conn_handle);
    
    switch (opcode) {
        case FMNA_SERVICE_DEBUG_OPCODE_SET_KEY_ROTATION_TIMEOUT:
            fmna_state_machine_set_key_rotation_timeout_ms(((set_key_rotation_timeout_packet_t *)data)->timeout_ms);
            response_status = RESPONSE_STATUS_SUCCESS;
            break;
            
        case FMNA_SERVICE_DEBUG_OPCODE_RESET:
            // "Reset" into Separated, beaconing secondary key.
            fmna_state_machine_dispatch_event(FMNA_SM_EVENT_DEBUG_RESET_INTO_SEPARATED);
            response_status = RESPONSE_STATUS_SUCCESS;
            break;
        
        case FMNA_SERVICE_DEBUG_OPCODE_RETRIEVE_LOGS:
            FMNA_LOG_INFO("RX Retrieve Logs");
            
            //TODO: Send all logs in multiple chunks, if applicable.
            
            // Send empty chunk of size GATT_MAX_MTU_SIZE --> this will get broken up into two messages.
            fmna_gatt_send_indication(conn_handle,
                                      FMNA_SERVICE_DEBUG_OPCODE_LOG_RESPONSE,
                                      m_log_chunk,
                                      GATT_MAX_MTU_SIZE);
            break;
            
        case FMNA_SERVICE_DEBUG_UT_MOTION_TIMERS_CONFIG: {
            ut_motion_timers_config_packet_t *packet = (ut_motion_timers_config_packet_t *)data;
            FMNA_LOG_INFO("Separated UT timeout: %d s -- Separated UT backoff timeout: %d s",
                          packet->separated_ut_timeout_seconds,
                          packet->separated_ut_backoff_timeout_seconds);
            
            fmna_state_machine_set_separated_ut_timeout_seconds(packet->separated_ut_timeout_seconds);
            fmna_motion_detection_set_separated_ut_backoff_timeout_seconds(packet->separated_ut_backoff_timeout_seconds);
            
            response_status = RESPONSE_STATUS_SUCCESS;
        } break;
            
        default:
            // We should never get here! rx_error_check should check for unknown command and respond with failed command response.
            FMNA_LOG_ERROR("Invalid opcode for debug control point received");
            FMNA_ERROR_CHECK(FMNA_ERROR_INVALID_STATE);
    }
    
    if (RESPONSE_STATUS_NO_COMMAND_RESPONSE != response_status) {
        // Send command response if this command needs one.
        fmna_gatt_send_command_response(FMNA_SERVICE_DEBUG_OPCODE_COMMAND_RESPONSE, conn_handle, opcode, response_status);
    }
}

#endif // DEBUG

