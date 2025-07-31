/*
 *      Copyright (C) 2020 Apple Inc. All Rights Reserved.
 *
 *      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
 *      which is contained in the License.txt file distributed with the Find My Network ADK,
 *      and only to those who accept that license.
 */

#include "fmna_platform_includes.h"
#include "fmna_nonowner_control_point.h"
#include "fmna_gatt.h"
#include "fmna_state_machine.h"
#include "fmna_connection.h"

typedef struct {
    uint16_t          opcode;
    FMNA_Response_Status_t status;
} __attribute__((packed)) non_owner_command_response_data_t;


//MARK: RX Packet Definitions

typedef struct {
    FMNA_Service_Opcode_t sound_start_opcode;
} __attribute__((packed)) nonowner_sound_start_packet_t;

typedef struct {
    FMNA_Service_Opcode_t sound_stop_opcode;
} __attribute__((packed)) nonowner_sound_stop_packet_t;

/// RX Length Check managers for default and variable length cases.
static fmna_service_length_check_manager_t rx_length_check_managers[] = \
{
    /* RX Opcode                                             Data Length */
    { FMNA_SERVICE_NON_OWNER_OPCODE_SOUND_START,             sizeof(nonowner_sound_start_packet_t)  },
    { FMNA_SERVICE_NON_OWNER_OPCODE_SOUND_STOP,              sizeof(nonowner_sound_stop_packet_t)   },
    { FMNA_SERVICE_NON_OWNER_OPCODE_START_AGGRESSIVE_ADV,    sizeof(generic_control_point_packet_t) },
};

bool m_aggressive_ut_adv_enabled = false;

static FMNA_Response_Status_t rx_error_check(uint16_t conn_handle, FMNA_Service_Opcode_t opcode, uint8_t const * data, uint16_t length) {
    if (fmna_state_machine_is_nearby() || fmna_connection_is_status_bit_enabled(conn_handle, FMNA_MULTI_STATUS_ENCRYPTED)) {
        FMNA_LOG_ERROR("non-owner command cannot be issued");
        return RESPONSE_STATUS_INVALID_COMMAND;
    }
    
    return fmna_gatt_verify_control_point_opcode_and_length(opcode, length, rx_length_check_managers, FMNA_SERVICE_LENGTH_CHECK_MANAGERS_SIZE(rx_length_check_managers));
}

void fmna_nonowner_rx_handler(uint16_t conn_handle, uint8_t const * data, uint16_t length){
    FMNA_Service_Opcode_t opcode = *(FMNA_Service_Opcode_t *)data;
    
    FMNA_Response_Status_t response_status = rx_error_check(conn_handle, opcode, data, length);
    if (response_status != RESPONSE_STATUS_SUCCESS) {
        FMNA_LOG_ERROR("Rx error 0x%x for opcode 0x%x, conn_handle 0x%x", response_status, opcode, conn_handle);
        if (response_status == RESPONSE_STATUS_INVALID_COMMAND) {
            opcode = FMNA_SERVICE_OPCODE_NONE;
        }
        fmna_gatt_send_command_response(FMNA_SERVICE_NON_OWNER_OPCODE_COMMAND_RESPONSE, conn_handle, opcode, response_status);
        return;
    }
    
    response_status = RESPONSE_STATUS_NO_COMMAND_RESPONSE;
    
    FMNA_LOG_INFO("Non-owner rx: opcode = 0x%x, conn_handle 0x%x", opcode, conn_handle);
    
    switch (opcode) {
        case FMNA_SERVICE_NON_OWNER_OPCODE_SOUND_START:
            FMNA_LOG_INFO("RX Non-owner Sound Start");
            if (fmna_connection_is_status_bit_enabled(CONN_HANDLE_ALL, FMNA_MULTI_STATUS_PLAYING_SOUND)) {
                FMNA_LOG_ERROR("Sound session already in progress");
                response_status = RESPONSE_STATUS_INVALID_STATE;
            } else {
                fmna_connection_update_connection_info(conn_handle, FMNA_MULTI_STATUS_PLAYING_SOUND, true);
                response_status = RESPONSE_STATUS_SUCCESS;
                fmna_state_machine_dispatch_event(FMNA_SM_EVENT_SOUND_START);
            }
            break;
            
        case FMNA_SERVICE_NON_OWNER_OPCODE_SOUND_STOP:
            FMNA_LOG_INFO("RX Non-owner Sound Stop");
            if (!fmna_connection_is_status_bit_enabled(CONN_HANDLE_ALL, FMNA_MULTI_STATUS_PLAYING_SOUND)) {
                FMNA_LOG_INFO("No sound session in progress");
                response_status = RESPONSE_STATUS_INVALID_STATE;
            } else{
                fmna_state_machine_dispatch_event(FMNA_SM_EVENT_SOUND_STOP);
            }
            break;
            
        case FMNA_SERVICE_NON_OWNER_OPCODE_START_AGGRESSIVE_ADV:
            FMNA_LOG_INFO("RX UT aggressive adv");
            
            // Set flag to Start advertising Separated mode aggressively on disconnect.
            m_aggressive_ut_adv_enabled = true;
            
            response_status = RESPONSE_STATUS_SUCCESS;
            break;
        
        default:
            // We should never get here! rx_error_check should check for unknown command and respond with failed command response.
            FMNA_LOG_ERROR("Invalid opcode for non-owner control point received");
            FMNA_ERROR_CHECK(FMNA_ERROR_INVALID_STATE);
    }
    
    if (RESPONSE_STATUS_NO_COMMAND_RESPONSE != response_status) {
        // Send command response for this command.
        fmna_gatt_send_command_response(FMNA_SERVICE_NON_OWNER_OPCODE_COMMAND_RESPONSE, conn_handle, opcode, response_status);
    }
    
}
