/*
 *      Copyright (C) 2020 Apple Inc. All Rights Reserved.
 *
 *      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
 *      which is contained in the License.txt file distributed with the Find My Network ADK,
 *      and only to those who accept that license.
 */

#include "fmna_platform_includes.h"

#include "fmna_constants.h"
#include "fmna_connection.h"
#include "fmna_gatt.h"
#include "fmna_state_machine.h"
#include "fmna_adv.h"
#include "fmna_config_control_point.h"
#include "fmna_pairing_control_point.h"
#include "fmna_peer_manager.h"
#include "fmna_nfc.h"
#include "fmna_crypto.h"

// Flag to determine whether we need to wait for disconnections to send
// set max connections response. 
static bool m_fmna_delayed_max_conn = false;

static bool m_is_fmna_paired = false;

fmna_active_conn_info_t m_fmna_active_connections[MAX_SUPPORTED_CONNECTIONS];

// Default 1 connection only
static uint8_t m_max_connections = 1;

// Unpair pending flag to keep track of unpair commit state.
static bool m_unpair_pending = false;

static uint8_t m_active_ltk[GAP_SEC_KEY_LEN];

//MARK: Private Functions

/// Initializes fmna_active_conn_info_t struct for this connection.
/// @details     Ensures valid connection handle and this connection does not already exist. Disconnect for invalid connection.
/// @param[in]   conn_intv       Negotiated connection interval.
static void init_connection_info(uint16_t conn_handle, uint16_t conn_intv) {
    // ensure connection handle is within number of allowed links
    bool is_valid_conn_handle = conn_handle < MAX_SUPPORTED_CONNECTIONS;
    
    if (   !is_valid_conn_handle
        // ensure this connection handle is not already allocated
        || (m_fmna_active_connections[conn_handle].conn_handle != CONN_HANDLE_INVALID)) {
        FMNA_LOG_ERROR("Invalid connection, disconnect conn_handle 0x%x", conn_handle);
        fmna_ret_code_t ret_code = fmna_connection_platform_disconnect(conn_handle);
        FMNA_ERROR_CHECK(ret_code);
    }
    
    // clear all the multi status bits
    memset(&(m_fmna_active_connections[conn_handle].multi_status), 0, sizeof(uint32_t));
    
    m_fmna_active_connections[conn_handle].conn_handle = conn_handle;
    m_fmna_active_connections[conn_handle].conn_intv   = conn_intv;
    
    //TODO: Set m_fmna_active_connections[conn_handle].conn_ts to current time in ticks.
}

/// Clears fmna_active_conn_info_t struct for this connection, on a disconnection.
/// @details     Link is already disconnected at this point. This function is cleanup.
static void clear_connection_info(uint16_t conn_handle) {
    // Ensure connection handle is within number of allowed links
    if (conn_handle >= MAX_SUPPORTED_CONNECTIONS) {
        FMNA_LOG_ERROR("Invalid disconnection, conn_handle 0x%x", conn_handle);
        return;
    }
    
    m_fmna_active_connections[conn_handle].conn_handle = CONN_HANDLE_INVALID;
}

/// Checks whether this connection has a particular multi status bit enabled.
/// @param[in]   status      Multi status bit to check.
/// @return True is this connection handle is a valid connection and has this multi status bit enabled. False otherwise.
static bool is_multi_status_bit_enabled(uint16_t conn_handle, FMNA_Multi_Status_t status) {
    if (!fmna_connection_is_valid_connection(conn_handle)) {
        return false;
    }
    
    return ((m_fmna_active_connections[conn_handle].multi_status & (1 << status)) != 0);
}

/// Get multi status of all active connections.
static uint32_t fmna_connection_get_multi_status_all(void) {
    uint32_t multi_status = 0;
    
    // Bitwise OR all the multi-statuses from all active connections.
    for (uint16_t conn_handle = 0; conn_handle < MAX_SUPPORTED_CONNECTIONS; conn_handle++) {
        if (m_fmna_active_connections[conn_handle].conn_handle != CONN_HANDLE_INVALID) {
            multi_status |= m_fmna_active_connections[conn_handle].multi_status;
        }
    }
    
    return multi_status;
}

/// Return whether multiple owners are currently connected.
///
/// @details    Go through all active connections, except the connection querying multi status,
///             and check encryption status.
///
/// @param  current_conn_handle      Handle of connection querying multi status.
///
/// @return True    If another connection, other than this connection, is encrypted. False, otherwise.
///
static bool is_multiple_owners_connected(uint16_t current_conn_handle) {
    for (uint16_t conn_handle = 0; conn_handle < MAX_SUPPORTED_CONNECTIONS; conn_handle++) {
        if (   conn_handle != current_conn_handle
            && m_fmna_active_connections[conn_handle].conn_handle != CONN_HANDLE_INVALID) {
            if (fmna_connection_is_status_bit_enabled(conn_handle, FMNA_MULTI_STATUS_ENCRYPTED)) {
                return true;
            }
        }
    }
    
    return false;
}

//MARK: Public Functions

void fmna_connection_init(void) {
    // Set all connection info to 0xFF so that, initially, all connection handles are invalid.
    memset(m_fmna_active_connections, 0xFF, sizeof(m_fmna_active_connections));
}

bool fmna_connection_is_valid_connection(uint16_t conn_handle) {
           // Ensure connection handle is within number of allowed links.
    if (   conn_handle >= MAX_SUPPORTED_CONNECTIONS
        // Ensure this is an active connection.
        || m_fmna_active_connections[conn_handle].conn_handle == CONN_HANDLE_INVALID) {
        return false;
    }
    return true;
}

bool fmna_connection_is_status_bit_enabled(uint16_t conn_handle, FMNA_Multi_Status_t status) {
    if (CONN_HANDLE_ALL != conn_handle) {
        return is_multi_status_bit_enabled(conn_handle, status);
    }
    
    // Check all connections to see if multi status bit is enabled
    for (uint16_t conn_handle = 0; conn_handle < MAX_SUPPORTED_CONNECTIONS; conn_handle++) {
        if (is_multi_status_bit_enabled(conn_handle, status)) {
            return true;
        }
    }
    return false;
}

uint16_t fmna_connection_get_conn_handle_with_multi_status_enabled(FMNA_Multi_Status_t status) {
    for (uint16_t conn_handle = 0; conn_handle < MAX_SUPPORTED_CONNECTIONS; conn_handle++) {
        if (is_multi_status_bit_enabled(conn_handle, status)) {
            return conn_handle;
        }
    }
    
    // No connection with that status bit enabled - return invalid
    return CONN_HANDLE_INVALID;
}

void fmna_connection_disconnect_all(void) {
    fmna_ret_code_t ret_code;
    
    for (uint16_t conn_handle = 0; conn_handle < m_max_connections; conn_handle++) {
        ret_code = fmna_connection_platform_disconnect(conn_handle);
        if (FMNA_SUCCESS != ret_code) {
            FMNA_LOG_ERROR("fmna_connection_platform_disconnect err 0x%x", ret_code);
        }
    }
}

void fmna_connection_disconnect_this(void) {
    fmna_ret_code_t ret_code = fmna_connection_platform_disconnect(fmna_gatt_get_most_recent_conn_handle());
    if (FMNA_SUCCESS != ret_code) {
        FMNA_LOG_ERROR("fmna_connection_platform_disconnect err 0x%x", ret_code);
    }
}

static uint32_t m_multi_status;
void fmna_connection_send_multi_status(uint16_t conn_handle) {
    m_multi_status = fmna_connection_get_multi_status_all();
    
    // Check if any other connection other than this connection is encrypted.
    if (is_multiple_owners_connected(conn_handle)) {
        // Set the bit
        m_multi_status |= (1 << FMNA_MULTI_STATUS_IS_MULTIPLE_OWNERS_CONNECTED);
    }
    
    fmna_gatt_send_indication(conn_handle, FMNA_SERVICE_OPCODE_GET_MULTI_STATUS_RESPONSE, &m_multi_status, sizeof(m_multi_status));
}

void fmna_connection_update_connection_info(uint16_t conn_handle, FMNA_Multi_Status_t status, bool enable) {
    if (!fmna_connection_is_valid_connection(conn_handle)) {
        FMNA_LOG_ERROR("Unable to update connection info for invalid conn_handle 0x%x", conn_handle);
        return;
    }
    
    if (enable) {
        // Set the bit
        m_fmna_active_connections[conn_handle].multi_status |= (1 << status);
    }
    else {
        // Clear the bit
        m_fmna_active_connections[conn_handle].multi_status &= ~(1 << status);
    }
}

void fmna_connection_update_connection_info_all(FMNA_Multi_Status_t status, bool enable) {
    for (uint8_t conn_handle = 0; conn_handle < MAX_SUPPORTED_CONNECTIONS; conn_handle++) {
        if (m_fmna_active_connections[conn_handle].conn_handle != CONN_HANDLE_INVALID) {
            fmna_connection_update_connection_info(conn_handle, status, enable);
        }
    }
}

uint8_t fmna_connection_get_num_connections(void) {
    uint8_t num_connections = 0;
    for (uint8_t i = 0; i < MAX_SUPPORTED_CONNECTIONS; i++) {
        if (m_fmna_active_connections[i].conn_handle != CONN_HANDLE_INVALID) {
            num_connections++;
        }
    }
    return num_connections;
}

void fmna_connection_set_max_connections(uint8_t max_connections, uint16_t conn_handle) {
    fmna_ret_code_t ret_code;
    
    // Check if provided max connections number is valid.
    if (max_connections == 0) {
        FMNA_LOG_ERROR("Cannot set max connections to 0.");
        return;
    } else if (max_connections > MAX_SUPPORTED_CONNECTIONS) {
        FMNA_LOG_ERROR("Maintaining %d simultaneous connections is not supported. Defaulting to max supported: %d connections.",
                      max_connections,
                      MAX_SUPPORTED_CONNECTIONS);
        max_connections = MAX_SUPPORTED_CONNECTIONS;
    }
    
    m_max_connections = max_connections;
    
    // Stop advertisement in preparation.
    fmna_adv_stop_adv();
    
    if (fmna_connection_get_num_connections() < m_max_connections) {
        // Room for more connections; (re)start advertiing Nearby.
        fmna_adv_init_nearby(m_fmna_current_primary_key.public_key);
        fmna_adv_start_slow_adv();
    }
    
    // Forced to accept only 1 connection. Disconnect all others (who didn't send this command).
    if (max_connections == 1) {
        for (uint16_t handle = 0; handle < MAX_SUPPORTED_CONNECTIONS; ++handle) {
            // For every valid, active connection that is not THIS connection...
            if (handle != conn_handle && m_fmna_active_connections[handle].conn_handle != CONN_HANDLE_INVALID) {
                // Disconnect. Set m_fmna_delayed_max_conn to respond to iOS max connections command
                // on disconnect confirm for all relevant connections.
                m_fmna_delayed_max_conn = true;
                ret_code = fmna_connection_platform_disconnect(handle);
                FMNA_ERROR_CHECK(ret_code);
            }
        }
    }
    
    if (!m_fmna_delayed_max_conn) {
        // No other connections to disconnect, respond immediately.
        fmna_gatt_send_command_response(FMNA_SERVICE_OPCODE_COMMAND_RESPONSE, conn_handle, FMNA_SERVICE_OPCODE_SET_MAX_CONNECTIONS, RESPONSE_STATUS_SUCCESS);
    }
}

// returns time in ms to set the non owner connection TO
// 0 means no timeout required
uint32_t fmna_connection_get_non_owner_timeout(void) {
    uint64_t timer_val = 0;
    uint64_t time_now = 0; //TODO: Actually get current time ticks.
    uint32_t timer_ticks = 0;
    
    for (uint8_t conn_handle = 0; conn_handle < MAX_SUPPORTED_CONNECTIONS; conn_handle++) {
        if ((m_fmna_active_connections[conn_handle].conn_handle != CONN_HANDLE_INVALID) &&
            !fmna_connection_is_status_bit_enabled(conn_handle, FMNA_MULTI_STATUS_ENCRYPTED)) {
            uint32_t temp_time = 0;
            
            if ((m_fmna_active_connections[conn_handle].conn_ts + fmna_state_machine_get_non_owner_connection_timeout()) > time_now) {
                temp_time = m_fmna_active_connections[conn_handle].conn_ts  + fmna_state_machine_get_non_owner_connection_timeout() - time_now;
            }
            else {
                // the timer has expired.  set the value to non-zero to make
                // sure it gets set to the minimum and the timer will immediately expire
                temp_time = 1;
            }
            // If zero take the current time. Or take it if the timeout is smaller
            if (timer_val == 0 || temp_time < timer_val) {
                timer_val = temp_time;
            }
        }
    }

    // convert ms to timer ticks
    if (timer_val) {
        timer_ticks = APP_TIMER_MIN_TIMEOUT_TICKS;
        if (MSEC_TO_TIMER_TICKS(timer_val) > timer_ticks) {
            timer_ticks = MSEC_TO_TIMER_TICKS(timer_val);
        }
    }

    return timer_ticks;
}

void fmna_connection_connected_handler(uint16_t conn_handle, uint16_t conn_interval) {
    FMNA_LOG_INFO("Connected, conn_handle 0x%x", conn_handle);
    
    // Initialize connection info for this new connection.
    init_connection_info(conn_handle, conn_interval);
                
    // Send the event into the state machine.
    fmna_evt_handler(FMNA_SM_EVENT_CONNECTED, NULL);
}

void fmna_connection_conn_param_update_handler(uint16_t conn_handle, uint16_t conn_interval) {
    FMNA_LOG_INFO("Connection parameters updated, conn_handle 0x%x", conn_handle);
    
    // Update the connection interval negotiated.
    m_fmna_active_connections[conn_handle].conn_intv = conn_interval;
}

void fmna_connection_disconnected_handler(uint16_t conn_handle, uint8_t disconnect_reason) {
    FMNA_LOG_INFO("Disconnected, conn_handle 0x%x, reason 0x%x", conn_handle, disconnect_reason);
    
    // Check if this is a persistent connection disconnection by confirming if this bit is set in multi status.
    bool is_persistent_connection_disconnection = fmna_connection_is_status_bit_enabled(conn_handle, FMNA_MULTI_STATUS_PERSISTENT_CONNECTION);
    
    // Clear this connection info.
    clear_connection_info(conn_handle);
    
    fmna_state_machine_dispatch_event(FMNA_SM_EVENT_DISCONNECTED);
    
    if (fmna_connection_is_fmna_paired() && fmna_connection_get_num_connections() > 0) {
        // Restart Nearby advertising if there is still room for more connections.
        if (fmna_connection_get_num_connections() < m_max_connections) {
            fmna_adv_init_nearby(m_fmna_current_primary_key.public_key);
            if (is_persistent_connection_disconnection) {
                fmna_adv_start_fast_adv();
            } else {
                fmna_adv_start_slow_adv();
            }
        }
    } else if (is_persistent_connection_disconnection) {
        fmna_state_machine_set_persistent_connection_disconnection(true);
    }

    if (m_fmna_delayed_max_conn && fmna_connection_get_num_connections() <= 1) {
        // All necessary disconnections to enforce ower max connections are complete,
        // clear the flag and send the response now.
        m_fmna_delayed_max_conn = false;
        
        // Check which connection is still up, e.g. the connection that enforced lower max connections count, and send response.
        fmna_gatt_send_command_response(FMNA_SERVICE_OPCODE_COMMAND_RESPONSE, fmna_connection_get_conn_handle_with_multi_status_enabled(FMNA_MULTI_STATUS_ENCRYPTED),
                                                        FMNA_SERVICE_OPCODE_SET_MAX_CONNECTIONS,
                                                        RESPONSE_STATUS_SUCCESS);
    }
}

/// Set the LTK to swap existing LTK with for connection.
void fmna_connection_set_active_ltk(uint8_t new_ltk[GAP_SEC_KEY_LEN]) {
    memcpy(m_active_ltk, new_ltk, GAP_SEC_KEY_LEN);
    FMNA_LOG_INFO("LTK:");
    FMNA_LOG_HEXDUMP_INFO(m_active_ltk, GAP_SEC_KEY_LEN);
}

uint8_t *fmna_connection_get_active_ltk(void) {
    return m_active_ltk;
}

void fmna_connection_set_is_fmna_paired(bool is_paired) {
    m_is_fmna_paired = is_paired;
}

bool fmna_connection_is_fmna_paired(void) {
    //TODO: Implement way to determine accessory paired status.
    
    return m_is_fmna_paired;
}

void fmna_connection_fmna_unpair(bool force_disconnect) {
    FMNA_LOG_INFO("FMNA unpair");
    
    fmna_ret_code_t ret_code;
    
    // Delete the bonds
    fmna_pm_delete_bonds();
    
    // reset address
    fmna_adv_reset_bd_addr();

    // stop key rotation timers
    fmna_state_machine_stop_key_rotation_timers();

    fmna_state_machine_set_persistent_connection_disconnection(false);
    m_max_connections = 1;
    
    // Force disconnect if specified and connection is active.
    if (force_disconnect) {
        for (uint8_t conn_handle = 0; conn_handle < MAX_SUPPORTED_CONNECTIONS; ++conn_handle) {
            if (m_fmna_active_connections[conn_handle].conn_handle != CONN_HANDLE_INVALID) {
                ret_code = fmna_connection_platform_disconnect(conn_handle);
                APP_ERROR_CHECK(ret_code);
            }
        }
    }
    
    fmna_connection_set_is_fmna_paired(false);

    // Other modules' unpair cleanup
    fmna_state_machine_clear_keys();
    fmna_nfc_load_unpaired_url();
    fmna_pairing_control_point_unpair();
    fmna_crypto_unpair();
    fmna_gatt_reset_queues();
}

uint8_t fmna_connection_get_max_connections(void) {
    return m_max_connections;
}

void fmna_connection_set_unpair_pending(bool enable) {
    m_unpair_pending = enable;
}

bool fmna_connection_get_unpair_pending(void) {
    return m_unpair_pending;
}
