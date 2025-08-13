/*
 *      Copyright (C) 2020 Apple Inc. All Rights Reserved.
 *
 *      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
 *      which is contained in the License.txt file distributed with the Find My Network ADK,
 *      and only to those who accept that license.
 */

#include "fmna_constants.h"
#include "fmna_platform_includes.h"
#include "fmna_pairing_control_point.h"

#include "fmna_crypto.h"
#include "fmna_gatt.h"
#include "fmna_connection.h"
#include "fmna_state_machine.h"
#include "fmna_storage.h"

//MARK: RX Packet Definitions

typedef struct {
    FMNA_Service_Opcode_t initiate_pairing_opcode;
    fmna_initiate_pairing_data_t initiate_pairing_data;
} __attribute__((packed)) initiate_pairing_packet_t;

typedef struct {
    FMNA_Service_Opcode_t finalize_pairing_opcode;
    fmna_finalize_pairing_data_t finalize_pairing_data;
} __attribute__((packed)) finalize_pairing_packet_t;

typedef struct {
    FMNA_Service_Opcode_t pairing_complete_opcode;
} __attribute__((packed)) pairing_complete_packet_t;

// General buffer to hold the incoming Pairing characteristic Write data
typedef struct {
    uint16_t len;
    uint8_t data[PAIRING_MAX_LEN];
} pairing_rx_buffer_t;

static pairing_rx_buffer_t pairing_rx_buffer = {};

/// RX Length Check managers for default and variable length cases.
static fmna_service_length_check_manager_t rx_length_check_managers[] = \
{
    /* RX Opcode                                 Data Length */
    { FMNA_SERVICE_OPCODE_INITIATE_PAIRING,   sizeof(initiate_pairing_packet_t) },
    { FMNA_SERVICE_OPCODE_FINALIZE_PAIRING,   sizeof(finalize_pairing_packet_t) },
    { FMNA_SERVICE_OPCODE_PAIRING_COMPLETE,   sizeof(pairing_complete_packet_t) },
};

static FMNA_Response_Status_t rx_error_check(FMNA_Service_Opcode_t opcode, uint8_t *data, uint16_t length) {
    FMNA_Response_Status_t response_status = fmna_gatt_verify_control_point_opcode_and_length(opcode, length, rx_length_check_managers, FMNA_SERVICE_LENGTH_CHECK_MANAGERS_SIZE(rx_length_check_managers));
    
    if (   (opcode == FMNA_SERVICE_OPCODE_FINALIZE_PAIRING)
        && (response_status == RESPONSE_STATUS_INVALID_LENGTH)) {
        // Bypass finalize pairing length check for now.
        //TODO: Add min max check for finalize pairing.
        response_status = RESPONSE_STATUS_SUCCESS;
    }
    
    return response_status;
}

void fmna_pairing_control_point_unpair(void) {
    //add other cleanup
    memset(&pairing_rx_buffer, 0, sizeof(pairing_rx_buffer));
    return;
}

fmna_ret_code_t fmna_pairing_control_point_append_to_rx_buffer(uint8_t const *data, uint16_t length) {
    
    if ((pairing_rx_buffer.len + length) > PAIRING_MAX_LEN) {
        FMNA_LOG_ERROR("Buffer too long");
        fmna_connection_fmna_unpair(true);
    }
    
    memcpy(&(pairing_rx_buffer.data[pairing_rx_buffer.len]), data, length);
    pairing_rx_buffer.len += length;
    
    return FMNA_SUCCESS;
}

void fmna_pairing_control_point_handle_rx(void) {
    FMNA_Service_Opcode_t opcode = *(FMNA_Service_Opcode_t *)pairing_rx_buffer.data;
    
    FMNA_Response_Status_t response_status = rx_error_check(opcode, (uint8_t *)&pairing_rx_buffer, pairing_rx_buffer.len);
    if (response_status != RESPONSE_STATUS_SUCCESS) {
        FMNA_LOG_ERROR("Rx error %d for opcode 0x%x", response_status, opcode);
        fmna_connection_fmna_unpair(true);
        return;
    }

    FMNA_LOG_INFO("Rx: Opcode = 0x%x", opcode);
    switch (opcode) {
        case FMNA_SERVICE_OPCODE_INITIATE_PAIRING:
            memcpy(&m_fmna_initiate_pairing_data,
                   &(((initiate_pairing_packet_t *)pairing_rx_buffer.data)->initiate_pairing_data), sizeof(m_fmna_initiate_pairing_data));
            fmna_state_machine_dispatch_event(FMNA_SM_EVENT_FMNA_PAIRING_INITIATE);
            break;
        
        case FMNA_SERVICE_OPCODE_FINALIZE_PAIRING:
            memcpy(&m_fmna_finalize_pairing_data,
                   &(((finalize_pairing_packet_t *)pairing_rx_buffer.data)->finalize_pairing_data),
                   sizeof(m_fmna_finalize_pairing_data));
            fmna_storage_write(FMNA_ICLOUD_ID, &m_fmna_finalize_pairing_data.icloud_id, ICLOUD_IDENTIFIER_BLEN);
            fmna_state_machine_dispatch_event(FMNA_SM_EVENT_FMNA_PAIRING_FINALIZE);
            break;
            
        case FMNA_SERVICE_OPCODE_PAIRING_COMPLETE:
            fmna_state_machine_dispatch_event(FMNA_SM_EVENT_FMNA_PAIRING_COMPLETE);
            break;

        default:
            break;
    }
    
    memset(&pairing_rx_buffer, 0, sizeof(pairing_rx_buffer));
}
