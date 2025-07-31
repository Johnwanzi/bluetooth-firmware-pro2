/*
 *      Copyright (C) 2020 Apple Inc. All Rights Reserved.
 *
 *      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
 *      which is contained in the License.txt file distributed with the Find My Network ADK,
 *      and only to those who accept that license.
 */

#include "fmna_platform_includes.h"
#include "fmna_config_control_point.h"
#include "fmna_gatt.h"
#include "fmna_state_machine.h"
#include "fmna_crypto.h"
#include "fmna_connection.h"
#include "fmna_adv.h"

typedef struct {
    uint16_t          opcode;
    FMNA_Response_Status_t status;
} __attribute__((packed)) command_response_data_t;

//MARK: RX Packet Definitions

typedef struct {
    FMNA_Service_Opcode_t persistent_connection_status_opcode;
    bool                  status;
} __attribute__((packed)) persistent_connection_status_packet_t;

typedef struct {
    FMNA_Service_Opcode_t set_nearby_timeout_opcode;
    uint16_t              timeout_seconds;
} __attribute__((packed)) set_nearby_timeout_packet_t;

typedef struct {
    FMNA_Service_Opcode_t configure_separated_state_opcode;
    uint32_t              next_key_roll_ms;
    uint32_t              secondary_key_evaluation_index;
} __attribute__((packed)) configure_separated_state_packet_t;

typedef struct {
    FMNA_Service_Opcode_t set_max_connections_opcode;
    uint8_t               max_connections;
} __attribute__((packed)) set_max_connections_packet_t;

typedef struct {
    FMNA_Service_Opcode_t set_utc_opcode;
    uint64_t              current_time;
} __attribute__((packed)) set_utc_packet_t;

/// RX Length Check managers for default and variable length cases.
static fmna_service_length_check_manager_t rx_length_check_managers[] = \
{
    /* RX Opcode                                             Data Length */
    { FMNA_SERVICE_OPCODE_SOUND_START,                    sizeof(generic_control_point_packet_t)        },
    { FMNA_SERVICE_OPCODE_SOUND_STOP,                     sizeof(generic_control_point_packet_t)        },
    { FMNA_SERVICE_OPCODE_PERSISTENT_CONNECTION_STATUS,   sizeof(persistent_connection_status_packet_t) },
    { FMNA_SERVICE_OPCODE_SET_NEARBY_TIMEOUT,             sizeof(set_nearby_timeout_packet_t)           },
    { FMNA_SERVICE_OPCODE_UNPAIR,                         sizeof(generic_control_point_packet_t)        },
    { FMNA_SERVICE_OPCODE_CONFIGURE_SEPARATED_STATE,      sizeof(configure_separated_state_packet_t)    },
    { FMNA_SERVICE_OPCODE_LATCH_SEPARATED_KEY,            sizeof(generic_control_point_packet_t)        },
    { FMNA_SERVICE_OPCODE_SET_MAX_CONNECTIONS,            sizeof(set_max_connections_packet_t)          },
    { FMNA_SERVICE_OPCODE_SET_UTC,                        sizeof(set_utc_packet_t)                      },
    { FMNA_SERVICE_OPCODE_GET_MULTI_STATUS,               sizeof(generic_control_point_packet_t)        },
};

static FMNA_Response_Status_t rx_error_check(uint16_t conn_handle, FMNA_Service_Opcode_t opcode, uint8_t const * data, uint16_t length) {
    // Reject config CP messages if we're not FMNA paired.
    if (!fmna_connection_is_fmna_paired()) {
        FMNA_LOG_ERROR("conn_handle 0x%x not FMNA paired, reject message.", conn_handle);
        return RESPONSE_STATUS_INVALID_STATE;
    }
    
    if (!fmna_connection_is_status_bit_enabled(conn_handle, FMNA_MULTI_STATUS_ENCRYPTED)) {
        // If this connection is not encrypted, do not allow config CP messages.
        FMNA_LOG_ERROR("conn_handle 0x%x not encrypted, reject.", conn_handle);
        return RESPONSE_STATUS_INVALID_STATE;
    }
    
    return fmna_gatt_verify_control_point_opcode_and_length(opcode, length, rx_length_check_managers, FMNA_SERVICE_LENGTH_CHECK_MANAGERS_SIZE(rx_length_check_managers));
}

void fmna_config_control_point_rx_handler(uint16_t conn_handle, uint8_t const * data, uint16_t length) {
    FMNA_Service_Opcode_t opcode = *(FMNA_Service_Opcode_t *)data;
    
    FMNA_Response_Status_t response_status = rx_error_check(conn_handle, opcode, data, length);
    if (response_status != RESPONSE_STATUS_SUCCESS) {
        FMNA_LOG_ERROR("Rx error 0x%x for opcode 0x%x, conn_handle 0x%x", response_status, opcode, conn_handle);
        if (response_status == RESPONSE_STATUS_INVALID_COMMAND) {
            opcode = FMNA_SERVICE_OPCODE_NONE;
        }
        fmna_gatt_send_command_response(FMNA_SERVICE_OPCODE_COMMAND_RESPONSE, conn_handle, opcode, response_status);
        return;
    }
    
    // Initialize response status, since we will send command response for expected commands at the end of the switch statement.
    // Commands that have their own responses will be handled within their case and will NOT send command response.
    response_status = RESPONSE_STATUS_NO_COMMAND_RESPONSE;
    
    FMNA_LOG_INFO("Configuration rx: opcode = 0x%x, conn_handle 0x%x", opcode, conn_handle);
    
    switch (opcode){
        case FMNA_SERVICE_OPCODE_SOUND_START: {
            FMNA_LOG_INFO("RX Sound Start");
            if (fmna_connection_is_status_bit_enabled(CONN_HANDLE_ALL, FMNA_MULTI_STATUS_PLAYING_SOUND)) {
                FMNA_LOG_ERROR("Sound session already in progress");
                response_status = RESPONSE_STATUS_INVALID_STATE;
            }
            else {
                // Update the multi status in case another play sound request comes before we execute play sound state machine handler.
                fmna_connection_update_connection_info(conn_handle, FMNA_MULTI_STATUS_PLAYING_SOUND, true);
                response_status = RESPONSE_STATUS_SUCCESS;
                fmna_state_machine_dispatch_event(FMNA_SM_EVENT_SOUND_START);
            }
        } break;

        case FMNA_SERVICE_OPCODE_SOUND_STOP: {
            FMNA_LOG_INFO("RX Sound Stop");
            if (!fmna_connection_is_status_bit_enabled(CONN_HANDLE_ALL, FMNA_MULTI_STATUS_PLAYING_SOUND)) {
                FMNA_LOG_WARNING("No sound session in progress");
                response_status = RESPONSE_STATUS_INVALID_STATE;
            }
            else {
                fmna_state_machine_dispatch_event(FMNA_SM_EVENT_SOUND_STOP);
            }
        } break;

        case FMNA_SERVICE_OPCODE_PERSISTENT_CONNECTION_STATUS: {
            persistent_connection_status_packet_t *packet = (persistent_connection_status_packet_t *)data;
            
            FMNA_LOG_INFO("RX Persistent Connection Status %d", packet->status);
            
            if (packet->status == false) {
                // Disable persistent connections.
                fmna_connection_update_connection_info(conn_handle, FMNA_MULTI_STATUS_PERSISTENT_CONNECTION, false);
            }
            //only set persistent connection if no other links are persistent
            else if (fmna_connection_is_status_bit_enabled(CONN_HANDLE_ALL, FMNA_MULTI_STATUS_PERSISTENT_CONNECTION) == false) {
                fmna_connection_update_connection_info(conn_handle, FMNA_MULTI_STATUS_PERSISTENT_CONNECTION, true);
                
                //start slow advertising
                if (fmna_state_machine_is_persistent_connection_disconnection() &&
                    (fmna_connection_get_num_connections() < fmna_connection_get_max_connections())) {
                    fmna_adv_init_nearby(m_fmna_current_primary_key.public_key);
                    fmna_adv_start_slow_adv();
                }
                fmna_state_machine_set_persistent_connection_disconnection(false);
            }
            
            response_status = RESPONSE_STATUS_SUCCESS;
        } break;
            
        case FMNA_SERVICE_OPCODE_SET_NEARBY_TIMEOUT: {
            set_nearby_timeout_packet_t *packet = (set_nearby_timeout_packet_t *)data;
            FMNA_LOG_INFO("RX Set Nearby Timeout, seconds: %d", packet->timeout_seconds);
            
            if (packet->timeout_seconds > NEARBY_TIMEOUT_MAX_SECONDS) {
                response_status = RESPONSE_STATUS_INVALID_PARAM;
            } else {
                fmna_state_machine_set_nearby_timeout_seconds(packet->timeout_seconds);
                response_status = RESPONSE_STATUS_SUCCESS;
            }
        } break;

        case FMNA_SERVICE_OPCODE_LATCH_SEPARATED_KEY:
            FMNA_LOG_INFO("RX Latch_Separated_Key");
            fmna_state_machine_latch_current_separated_key(conn_handle);
            break;
            
        case FMNA_SERVICE_OPCODE_SET_MAX_CONNECTIONS: {
            set_max_connections_packet_t *packet = (set_max_connections_packet_t *)data;
            
            FMNA_LOG_INFO("RX Set_Max_Connections to %d", packet->max_connections);
            
            fmna_connection_set_max_connections(packet->max_connections, conn_handle);
        } break;

        case FMNA_SERVICE_OPCODE_UNPAIR:
            FMNA_LOG_INFO("RX Unpair");
            
            if (   (fmna_connection_get_max_connections() > 1)
                || (fmna_connection_get_num_connections() != 1)) {
                // Unpair not allowed unless iOS sets max connections to 1
                // and only one central is connected to us.
         
                response_status = RESPONSE_STATUS_INVALID_STATE;
            } else {
                fmna_connection_set_unpair_pending(true);
                response_status = RESPONSE_STATUS_SUCCESS;
            }
            break;

        case FMNA_SERVICE_OPCODE_CONFIGURE_SEPARATED_STATE: {
            FMNA_LOG_INFO("RX Configure Separated State");
            configure_separated_state_packet_t *packet = (configure_separated_state_packet_t *)data;
            
            if (   ((packet->secondary_key_evaluation_index + SEPARATED_STATE_CONFIG_NEGATIVE_BOUNDARY) < m_fmna_current_primary_key.index)
                || (packet->secondary_key_evaluation_index > (m_fmna_current_primary_key.index + PRIMARY_KEYS_PER_SECONDARY_KEY))) {
                FMNA_LOG_ERROR("invalid Separated Mode Config Index: %d", packet->secondary_key_evaluation_index);
                response_status = RESPONSE_STATUS_INVALID_PARAM;
                break;
            }
            
            if (packet->next_key_roll_ms > m_fmna_key_rotation_timeout_ms) {
                FMNA_LOG_ERROR("invalid Separated Mode Config next keyroll ms: %d", packet->next_key_roll_ms);
                response_status = RESPONSE_STATUS_INVALID_PARAM;
                break;
            }
            
            fmna_state_machine_set_next_secondary_key_rotation_index(conn_handle, packet->secondary_key_evaluation_index);
            fmna_state_machine_set_next_keyroll_ms(packet->next_key_roll_ms);
        } break;

        case FMNA_SERVICE_OPCODE_SET_UTC:
            FMNA_LOG_INFO("Set_UTC command received");
            //TODO: Set UTC here
            response_status = RESPONSE_STATUS_SUCCESS;
            break;

        case FMNA_SERVICE_OPCODE_GET_MULTI_STATUS:
            FMNA_LOG_INFO("RX Get Multi Status");
            fmna_connection_send_multi_status(conn_handle);
            break;

        default:
            // We should never get here! rx_error_check should check for unknown command and respond with failed command response.
            FMNA_LOG_ERROR("Invalid opcode for configuration control point received");
            FMNA_ERROR_CHECK(FMNA_ERROR_INVALID_STATE);
    }
    
    if (RESPONSE_STATUS_NO_COMMAND_RESPONSE != response_status) {
        // Send command response if this command needs one.
        fmna_gatt_send_command_response(FMNA_SERVICE_OPCODE_COMMAND_RESPONSE, conn_handle, opcode, response_status);
    }
}

bool fmna_config_control_point_is_tx_allowed(uint16_t conn_handle, FMNA_Service_Opcode_t opcode) {
    bool is_tx_allowed = true;
    
    if (!fmna_connection_is_fmna_paired() || !fmna_connection_is_status_bit_enabled(conn_handle, FMNA_MULTI_STATUS_ENCRYPTED)) {
        FMNA_LOG_ERROR("Reject TX opcode 0x%x, conn_handle 0x%x. FMNA paired? %d, Encrypted? %d",
                       opcode,
                       conn_handle,
                       fmna_connection_is_fmna_paired(),
                       fmna_connection_is_status_bit_enabled(conn_handle, FMNA_MULTI_STATUS_ENCRYPTED));
        is_tx_allowed = false;
    }
    
    return is_tx_allowed;
}
