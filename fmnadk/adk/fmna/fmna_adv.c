/*
 *      Copyright (C) 2020 Apple Inc. All Rights Reserved.
 *
 *      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
 *      which is contained in the License.txt file distributed with the Find My Network ADK,
 *      and only to those who accept that license.
 */

#include "fmna_util.h"
#include "fmna_constants.h"
#include "fmna_adv.h"
#include "fmna_state_machine.h"
#include "fmna_battery_platform.h"
#include "fmna_gatt.h" // current_key_index

#define ADV_TYPE_FIND_MY                                         0x12

#define FMNA_ADV_STATUS_DEVICE_TYPE_FIND_MY                      0x2

// bit position, e.g. bit 0 is position 0
#define FMNA_ADV_STATUS_FLAG_DEVICE_TYPE_BITS_START_POS          4
#define FMNA_ADV_STATUS_FLAG_DEVICE_TYPE_BITS_LENGTH             2
#define FMNA_ADV_STATUS_FLAG_BATTERY_BITS_START_POS              6
#define FMNA_ADV_STATUS_FLAG_BATTERY_BITS_LENGTH                 2
#define FMNA_ADV_STATUS_FLAG_MAINTENANCED_BIT_POS                2

// Separated fast advertising is used for UT finding, e.g. aggressive adv.
#define FMNA_SEPARATED_ADV_FAST_INTERVAL                         0x30          /**< Fast advertising interval 30ms (in units of 0.625 ms.) */
#define FMNA_SEPARATED_ADV_FAST_DURATION                         12000         /**< The advertising duration of fast advertising 2 minutes (in units of 10 milliseconds.) */
#define FMNA_SEPARATED_ADV_SLOW_INTERVAL                         0xC80         /**< Slow advertising interval 2 seconds (in units of 0.625 ms.) */
#define FMNA_SEPARATED_ADV_SLOW_DURATION                         0             /**< The advertising duration of slow advertising forever (in units of 10 milliseconds.) */

static fmna_separated_adv_packet_t m_fmna_separated_adv_packet = {0};

uint16_t fmna_separated_adv_fast_intv                          = FMNA_SEPARATED_ADV_FAST_INTERVAL;
uint32_t fmna_separated_adv_fast_duration                      = FMNA_SEPARATED_ADV_FAST_DURATION;
uint16_t fmna_separated_adv_slow_intv                          = FMNA_SEPARATED_ADV_SLOW_INTERVAL;
uint32_t fmna_separated_adv_slow_duration                      = FMNA_SEPARATED_ADV_SLOW_DURATION;

// Nearby fast advertising is used for leash break. 
#define FMNA_NEARBY_ADV_FAST_INTERVAL                            0x30          /**< Fast advertising interval 30ms (in units of 0.625 ms.) */
#define FMNA_NEARBY_ADV_FAST_DURATION                            300           /**< The advertising duration of fast advertising 3s (in units of 10 milliseconds.) */
#define FMNA_NEARBY_ADV_SLOW_INTERVAL                            0xC80         /**< Slow advertising interval 2 seconds (in units of 0.625 ms.) */
#define FMNA_NEARBY_ADV_SLOW_DURATION                            0             /**< The advertising duration of slow advertising forever (in units of 10 milliseconds.) */

static fmna_nearby_adv_packet_t m_fmna_nearby_adv_packet       = {0};

uint16_t fmna_nearby_adv_fast_intv                             = FMNA_NEARBY_ADV_FAST_INTERVAL;
uint32_t fmna_nearby_adv_fast_duration                         = FMNA_NEARBY_ADV_FAST_DURATION;
uint16_t fmna_nearby_adv_intv                                  = FMNA_NEARBY_ADV_SLOW_INTERVAL;
uint32_t fmna_nearby_adv_duration                              = FMNA_NEARBY_ADV_SLOW_DURATION;

#define FMNA_PAIRING_ADV_FAST_INTERVAL                           0x30          /**< Fast advertising interval 30ms (in units of 0.625 ms.) */
#define FMNA_PAIRING_ADV_FAST_DURATION                           300           /**< The advertising duration of fast advertising 3s (in units of 10 milliseconds.) */
#define FMNA_PAIRING_ADV_SLOW_INTERVAL                           0x30          /**< Slow advertising interval 30ms (in units of 0.625 ms.) */
#define FMNA_PAIRING_ADV_SLOW_DURATION                           0             /**< The advertising duration of slow advertising forever (in units of 10 milliseconds.) */

static fmna_pairing_payload_t m_fmna_pairing_adv_payload       = {0};

uint16_t fmna_pairing_adv_fast_intv                            = FMNA_PAIRING_ADV_FAST_INTERVAL;
uint32_t fmna_pairing_adv_fast_duration                        = FMNA_PAIRING_ADV_FAST_DURATION;
uint16_t fmna_pairing_adv_slow_intv                            = FMNA_PAIRING_ADV_SLOW_INTERVAL;
uint32_t fmna_pairing_adv_slow_duration                        = FMNA_PAIRING_ADV_SLOW_DURATION;

void fmna_adv_reset_bd_addr(void) {
    uint8_t default_bt_addr[FMNA_BLE_MAC_ADDR_BLEN];
    
    fmna_adv_platform_get_default_bt_addr(default_bt_addr);
    
    // set address type bits for random static (0b11)
    default_bt_addr[0] |= (uint8_t)FMNA_ADV_ADDR_TYPE_MASK;
    
    fmna_adv_platform_set_random_static_bt_addr(default_bt_addr);
}

/// Overwrite the Bluetooth MAC address with the first 6 bytes of the public key..
/// @details     Top 2 bits of MSB  should be set to 0b11 for Random Static GAP address type.
/// @param[in]   current_pubkey      Current key to set BT MAC address to.
/// @return      Original top 2 bits of MSB to include in Find My ADV, so iOS can restore key.
static uint8_t overwrite_bd_addr(uint8_t current_pubkey[FMNA_PUBKEY_BLEN]) {
    uint8_t new_bt_mac[FMNA_BLE_MAC_ADDR_BLEN];
    
    memcpy(new_bt_mac, current_pubkey, FMNA_BLE_MAC_ADDR_BLEN);
    
    // Set address type bits of public key bd_addr for random static, 0b11.
    new_bt_mac[0] |= (uint8_t)FMNA_ADV_ADDR_TYPE_MASK;
    
    fmna_adv_platform_set_random_static_bt_addr(new_bt_mac);

    // Return original address type bits of public key bd_addr --> most significant bits
    return ((current_pubkey[0] & FMNA_ADV_ADDR_TYPE_MASK) >> FMNA_ADV_OPT_ADDR_TYPE_SHIFT);
}

static uint8_t get_fmna_status_flags_batt_bitfield(void) {
    uint8_t bat_level = fmna_battery_platform_get_battery_level();
    
    return ((uint8_t)(BF_VAL(bat_level,
                             FMNA_ADV_STATUS_FLAG_BATTERY_BITS_LENGTH,
                             FMNA_ADV_STATUS_FLAG_BATTERY_BITS_START_POS)));
}

static uint8_t get_fmna_status_flags_device_type_bitfield(void) {
    return ((uint8_t)(BF_VAL(FMNA_ADV_STATUS_DEVICE_TYPE_FIND_MY,
                             FMNA_ADV_STATUS_FLAG_DEVICE_TYPE_BITS_LENGTH,
                             FMNA_ADV_STATUS_FLAG_DEVICE_TYPE_BITS_START_POS)));
}

/// Fills Pairing payload according to ADV spec.
static void fmna_pairing_adv_service_data_init(void) {
    uint8_t product_data[PRODUCT_DATA_BLEN] = PRODUCT_DATA_VAL;
    memcpy(m_fmna_pairing_adv_payload.product_data,
           product_data,
           PRODUCT_DATA_BLEN);

    memset(m_fmna_pairing_adv_payload.acc_category, ACCESSORY_CATEGORY, sizeof(uint8_t));
    m_fmna_pairing_adv_payload.battery_state = fmna_battery_platform_get_battery_level();
}

/// Fills Nearby payload according to ADV spec.
/// @param[in]   current_pubkey      Current FMNA primary key to use as BT MAC address.
static void fmna_nearby_adv_manuf_data_init(uint8_t current_pubkey[FMNA_PUBKEY_BLEN]) {
    uint8_t pubkey_orig_addr_type_bits = overwrite_bd_addr(current_pubkey);
    
    m_fmna_nearby_adv_packet.fmna_nearby_payload.opt         = 0;
    m_fmna_nearby_adv_packet.fmna_nearby_payload.opt        |= pubkey_orig_addr_type_bits;
    
    m_fmna_nearby_adv_packet.type        = ADV_TYPE_FIND_MY;
    m_fmna_nearby_adv_packet.length      = sizeof(struct fmna_nearby_payload_s);
    
    m_fmna_nearby_adv_packet.fmna_nearby_payload.status = 0;
    m_fmna_nearby_adv_packet.fmna_nearby_payload.status |= get_fmna_status_flags_batt_bitfield();
    m_fmna_nearby_adv_packet.fmna_nearby_payload.status |= get_fmna_status_flags_device_type_bitfield();

    if (fmna_state_machine_has_been_maintenanced()) {
        SET_BIT(m_fmna_nearby_adv_packet.fmna_nearby_payload.status, FMNA_ADV_STATUS_FLAG_MAINTENANCED_BIT_POS);
    }
}

/// Fills Separated payload according to ADV spec.
/// @param[in]   separated_pubkey      Current FMNA primary separated key to use as BT MAC address.
/// @param[in]   hint                                 Current primary key hint for LTK reconciliation.
static void fmna_separated_adv_manuf_data_init(uint8_t separated_pubkey[FMNA_PUBKEY_BLEN], uint8_t hint) {
    uint8_t pubkey_orig_addr_type_bits = overwrite_bd_addr(separated_pubkey);
    
    m_fmna_separated_adv_packet.fmna_separated_payload.extra = 0;
    m_fmna_separated_adv_packet.fmna_separated_payload.extra |= pubkey_orig_addr_type_bits;
    m_fmna_separated_adv_packet.fmna_separated_payload.hint = hint;
    
    m_fmna_separated_adv_packet.type        = ADV_TYPE_FIND_MY;
    m_fmna_separated_adv_packet.length      = sizeof(struct fmna_separated_payload_s);

    m_fmna_separated_adv_packet.fmna_separated_payload.status = 0;
    m_fmna_separated_adv_packet.fmna_separated_payload.status |= get_fmna_status_flags_batt_bitfield();
    m_fmna_separated_adv_packet.fmna_separated_payload.status |= get_fmna_status_flags_device_type_bitfield();
    
    // Copy 22 bytes from the public key provided to the manufacturer payload buffer
    memcpy(m_fmna_separated_adv_packet.fmna_separated_payload.pubkey2,
           separated_pubkey + FMNA_BLE_MAC_ADDR_BLEN,
           FMNA_SEPARATED_ADV_PAYLOAD_PUBKEY_BLEN);
}

void fmna_adv_init_pairing(void) {
    fmna_pairing_adv_service_data_init();

    fmna_adv_platform_init_pairing((uint8_t *)&m_fmna_pairing_adv_payload, sizeof(m_fmna_pairing_adv_payload));
}

void fmna_adv_init_separated(uint8_t separated_pubkey[FMNA_PUBKEY_BLEN], uint8_t hint) {
    // Initialize separated manufacturing data with the separated public key and hint
    fmna_separated_adv_manuf_data_init(separated_pubkey, hint);
    
    fmna_adv_platform_init_separated((uint8_t *)&m_fmna_separated_adv_packet, sizeof(m_fmna_separated_adv_packet));
}

void fmna_adv_init_nearby(uint8_t pubkey[FMNA_PUBKEY_BLEN]) {
    // Initialize Nearby manufacturing data with the public key
    fmna_nearby_adv_manuf_data_init(pubkey);
    
    fmna_adv_platform_init_nearby((uint8_t *)&m_fmna_nearby_adv_packet, sizeof(m_fmna_nearby_adv_packet));
}
