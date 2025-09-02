#include <stdint.h>
#include "ble.h"
#include "ble_conn_params.h"
#include "ble_conn_state.h"
#include "nrf_sdh.h"
#include "nrf_sdh_soc.h"
#include "nrf_sdh_ble.h"
#include "nrf_ble_gatt.h"
#include "nrf_ble_qwr.h"
#include "app_timer.h"
#include "peer_manager_handler.h"

#include "ble_advdata.h"
#include "firmware_config.h"
#include "ok_ble_internal.h"
#include "ok_platform.h"
#include "fmna_app.h"

#define BLE_GAP_DATA_LENGTH_DEFAULT    27  //!< The stack's default data length.
#define BLE_GAP_DATA_LENGTH_MAX        251 //!< Maximum data length.

#define MIN_CONN_INTERVAL              MSEC_TO_UNITS(20, UNIT_1_25_MS) /**< Minimum acceptable connection interval (10 ms). */
#define MAX_CONN_INTERVAL              MSEC_TO_UNITS(40, UNIT_1_25_MS) /**< Maximum acceptable connection interval (100 ms) */
#define SLAVE_LATENCY                  0                               /**< Slave latency. */
#define CONN_SUP_TIMEOUT               MSEC_TO_UNITS(3000, UNIT_10_MS) /**< Connection supervisory timeout (4 seconds). */
#define FIRST_CONN_PARAMS_UPDATE_DELAY APP_TIMER_TICKS(500)
#define NEXT_CONN_PARAMS_UPDATE_DELAY  APP_TIMER_TICKS(5000)
#define MAX_CONN_PARAM_UPDATE_COUNT    3

#define ADV_NAME_LENGTH                12

#ifndef OPCODE_LENGTH
#define OPCODE_LENGTH 1
#endif

#ifndef HANDLE_LENGTH
#define HANDLE_LENGTH 2
#endif

NRF_BLE_GATT_DEF(m_gatt);
NRF_BLE_QWR_DEF(m_qwr);

static uint16_t m_conn_handle = BLE_CONN_HANDLE_INVALID; /**< Handle of the current connection. */
static char     ble_adv_name[ADV_NAME_LENGTH];

static uint16_t m_ble_gatt_max_data_len = BLE_GATT_ATT_MTU_DEFAULT - 3;

/// Function for checking whether a bluetooth stack event is an advertising timeout.
/// @param p_ble_evt Bluetooth stack event.
static bool ble_evt_is_advertising_timeout(ble_evt_t const * p_ble_evt) 
{
    return (p_ble_evt->header.evt_id == BLE_GAP_EVT_ADV_SET_TERMINATED);
}

/**@brief Function for handling BLE events.
 *
 * @param[in]   p_ble_evt   Bluetooth stack event.
 * @param[in]   p_context   Unused.
 */
static void ble_evt_handler(const ble_evt_t *p_ble_evt, void *p_context)
{
    uint16_t conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
    uint16_t role        = ble_conn_state_role(conn_handle);
    
    // based on the role this device plays in the connection, dispatch to the right handler
    if (role == BLE_GAP_ROLE_PERIPH || ble_evt_is_advertising_timeout(p_ble_evt)) {
        ble_adv_manage_event(p_ble_evt);
    }
}

// Initializes the SoftDevice and the BLE event interrupt.
static void ble_stack_init(void)
{
    ret_code_t err_code;

    err_code = nrf_sdh_enable_request();
    APP_ERROR_CHECK(err_code);

    // Configure the BLE stack using the default settings.
    // Fetch the start address of the application RAM.
    uint32_t ram_start = 0;
    err_code           = nrf_sdh_ble_default_cfg_set(APP_BLE_CONN_CFG_TAG, &ram_start);
    APP_ERROR_CHECK(err_code);

    // Enable BLE stack.
    err_code = nrf_sdh_ble_enable(&ram_start);
    APP_ERROR_CHECK(err_code);

    // Register a handler for BLE events.
    NRF_SDH_BLE_OBSERVER(m_ble_observer, APP_BLE_OBSERVER_PRIO, ble_evt_handler, NULL);
}

static void peer_manager_init(void)
{
#ifdef BOND_ENABLE
    ok_peer_manager_init();
#endif
}

// This function sets up all the necessary GAP (Generic Access Profile) parameters of the
// device including the device name, appearance, and the preferred connection parameters.
static void gap_params_init(void)
{
    ret_code_t              err_code;
    ble_gap_conn_params_t   gap_conn_params;
    ble_gap_conn_sec_mode_t sec_mode;

    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&sec_mode);

    ble_gap_addr_t gap_addr;
    sd_ble_gap_addr_get(&gap_addr);

    memset(ble_adv_name, 0x00, sizeof(ble_adv_name));
    strncpy(ble_adv_name, (char *)ADV_HEAD_NAME, strlen(ADV_HEAD_NAME));
    sprintf(ble_adv_name + strlen(ADV_HEAD_NAME), "%02X%02X", gap_addr.addr[1], gap_addr.addr[0]);

    err_code = sd_ble_gap_device_name_set(&sec_mode, (const uint8_t *)ble_adv_name, strlen(ble_adv_name));
    APP_ERROR_CHECK(err_code);

    memset(&gap_conn_params, 0, sizeof(gap_conn_params));

    gap_conn_params.min_conn_interval = MIN_CONN_INTERVAL;
    gap_conn_params.max_conn_interval = MAX_CONN_INTERVAL;
    gap_conn_params.slave_latency     = SLAVE_LATENCY;
    gap_conn_params.conn_sup_timeout  = CONN_SUP_TIMEOUT;

    err_code = sd_ble_gap_ppcp_set(&gap_conn_params);
    APP_ERROR_CHECK(err_code);
}

// Function for handling events from the GATT library. */
void gatt_evt_handler(nrf_ble_gatt_t *p_gatt, const nrf_ble_gatt_evt_t *p_evt)
{
    if ((m_conn_handle == p_evt->conn_handle) && (p_evt->evt_id == NRF_BLE_GATT_EVT_ATT_MTU_UPDATED)) {
        m_ble_gatt_max_data_len = p_evt->params.att_mtu_effective - OPCODE_LENGTH - HANDLE_LENGTH;
        NRF_LOG_INFO("Data len is set to 0x%X(%d)", m_ble_gatt_max_data_len, m_ble_gatt_max_data_len);
    }
    NRF_LOG_DEBUG("ATT MTU exchange completed. central 0x%x peripheral 0x%x", p_gatt->att_mtu_desired_central, p_gatt->att_mtu_desired_periph);
}

// Function for initializing the GATT module.
static void gatt_init(void)
{
    ret_code_t err_code;

    err_code = nrf_ble_gatt_init(&m_gatt, gatt_evt_handler);
    APP_ERROR_CHECK(err_code);

    err_code = nrf_ble_gatt_att_mtu_periph_set(&m_gatt, NRF_SDH_BLE_GATT_MAX_MTU_SIZE);
    APP_ERROR_CHECK(err_code);
}

/**@brief Function for handling Queued Write Module errors.
 *
 * @details A pointer to this function will be passed to each service which may need to inform the
 *          application about an error.
 *
 * @param[in]   nrf_error   Error code containing information about what went wrong.
 */
static void nrf_qwr_error_handler(uint32_t nrf_error)
{
    APP_ERROR_HANDLER(nrf_error);
}

/**@brief Function for initializing services that will be used by the application.
 *
 * @details Initialize the Glucose, Battery and Device Information services.
 */
static void services_init(void)
{
    ret_code_t         err_code;
    nrf_ble_qwr_init_t qwr_init = {0};

    // Initialize Queued Write Module.
    qwr_init.error_handler = nrf_qwr_error_handler;

    err_code = nrf_ble_qwr_init(&m_qwr, &qwr_init);
    APP_ERROR_CHECK(err_code);

    ok_bas_service_init();
    ok_trans_service_init();
    ok_fido_service_init();

#if BLE_DIS_ENABLED
    // Initialize Device Information Service.
    ok_dev_info_service_init();
#endif
}

static void advertising_init(void)
{
    ble_adv_manage_init();
    ok_ble_adv_init();

    ble_gap_addr_t gap_addr = {0};
    sd_ble_gap_addr_get(&gap_addr);
    NRF_LOG_INFO("MAC: %02X:%02X:%02X:%02X:%02X:%02X", gap_addr.addr[5], gap_addr.addr[4], gap_addr.addr[3], gap_addr.addr[2], gap_addr.addr[1], gap_addr.addr[0]);
    ble_adv_manage_update(BLE_ONEKEY_ADV_E, BLE_MANAGE_UPDATE_MAC_ADDR, &gap_addr);
}

/**@brief Function for handling the Connection Parameter events.
 *
 * @details This function will be called for all events in the Connection Parameters Module which
 *          are passed to the application.
 *          @note All this function does is to disconnect. This could have been done by simply
 *                setting the disconnect_on_fail configuration parameter, but instead we use the
 *                event handler mechanism to demonstrate its use.
 *
 * @param[in] p_evt  Event received from the Connection Parameters Module.
 */
static void on_conn_params_evt(ble_conn_params_evt_t *p_evt)
{
    ret_code_t err_code;

    if (p_evt->evt_type == BLE_CONN_PARAMS_EVT_FAILED) {
        err_code = sd_ble_gap_disconnect(m_conn_handle, BLE_HCI_CONN_INTERVAL_UNACCEPTABLE);
        APP_ERROR_CHECK(err_code);
    }
}

/**@brief Function for handling a Connection Parameters error.
 *
 * @param[in] nrf_error  Error code containing information about what went wrong.
 */
static void conn_params_error_handler(uint32_t nrf_error)
{
    APP_ERROR_HANDLER(nrf_error);
}


// Function for initializing the Connection Parameters module.
static void conn_params_init(void)
{
    ret_code_t             err_code;
    ble_conn_params_init_t cp_init;

    memset(&cp_init, 0, sizeof(cp_init));

    cp_init.p_conn_params                  = NULL;
    cp_init.first_conn_params_update_delay = FIRST_CONN_PARAMS_UPDATE_DELAY;
    cp_init.next_conn_params_update_delay  = NEXT_CONN_PARAMS_UPDATE_DELAY;
    cp_init.max_conn_params_update_count   = MAX_CONN_PARAM_UPDATE_COUNT;
    cp_init.start_on_notify_cccd_handle    = BLE_GATT_HANDLE_INVALID;
    cp_init.disconnect_on_fail             = false;
    cp_init.evt_handler                    = on_conn_params_evt;
    cp_init.error_handler                  = conn_params_error_handler;

    err_code = ble_conn_params_init(&cp_init);
    APP_ERROR_CHECK(err_code);
}

void ok_ble_evt_handler(ble_evt_t const *p_ble_evt)
{
    ret_code_t err_code;

    switch (p_ble_evt->header.evt_id) {
        case BLE_GAP_EVT_CONNECTED:
            NRF_LOG_INFO("Connected");
            m_conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
            err_code      = nrf_ble_qwr_conn_handle_assign(&m_qwr, m_conn_handle);
            APP_ERROR_CHECK(err_code);

            nrf_ble_gatt_data_length_set(&m_gatt, m_conn_handle, BLE_GAP_DATA_LENGTH_MAX);

            ok_peer_manage_update();
            break;

        case BLE_GAP_EVT_DISCONNECTED:
            NRF_LOG_INFO("Disconnected");
            // LED indication will be changed when advertising starts.
            m_conn_handle = BLE_CONN_HANDLE_INVALID;
            break;

        case BLE_GAP_EVT_PHY_UPDATE_REQUEST: {
            NRF_LOG_INFO("PHY update request.");
            const ble_gap_phys_t phys = {
                .rx_phys = BLE_GAP_PHY_AUTO,
                .tx_phys = BLE_GAP_PHY_AUTO,
            };
            err_code = sd_ble_gap_phy_update(p_ble_evt->evt.gap_evt.conn_handle, &phys);
            APP_ERROR_CHECK(err_code);
        } break;

        case BLE_GAP_EVT_SEC_PARAMS_REQUEST:
            // Pairing not supported
            NRF_LOG_INFO("Gap sec params request.");
            if (!ok_is_peer_manager_enable()) {
                err_code = sd_ble_gap_sec_params_reply(m_conn_handle, BLE_GAP_SEC_STATUS_PAIRING_NOT_SUPP, NULL, NULL);
                APP_ERROR_CHECK(err_code);
            }
            break;

        case BLE_GATTS_EVT_SYS_ATTR_MISSING:
            // No system attributes have been stored.
            NRF_LOG_INFO("Gatt sys attr missing.");
            err_code = sd_ble_gatts_sys_attr_set(m_conn_handle, NULL, 0, 0);
            APP_ERROR_CHECK(err_code);
            break;

        case BLE_GATTC_EVT_TIMEOUT:
            // Disconnect on GATT Client timeout event.
            NRF_LOG_INFO("Gattc evt timeout.");
            err_code = sd_ble_gap_disconnect(p_ble_evt->evt.gattc_evt.conn_handle, BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
            APP_ERROR_CHECK(err_code);
            break;

        case BLE_GATTS_EVT_TIMEOUT:
            // Disconnect on GATT Server timeout event.
            NRF_LOG_INFO("Gatts evt timeout.");
            err_code = sd_ble_gap_disconnect(p_ble_evt->evt.gatts_evt.conn_handle, BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
            APP_ERROR_CHECK(err_code);
            break;

        case BLE_GAP_EVT_CONN_PARAM_UPDATE:
            NRF_LOG_INFO("min %d, max %d, latency %d, timeout %d", 
                         p_ble_evt->evt.gap_evt.params.connected.conn_params.min_conn_interval,
                         p_ble_evt->evt.gap_evt.params.connected.conn_params.max_conn_interval,
                         p_ble_evt->evt.gap_evt.params.connected.conn_params.slave_latency,
                         p_ble_evt->evt.gap_evt.params.connected.conn_params.conn_sup_timeout);
            break;

        default:
            // No implementation needed.
            OK_LOG_INFO_NOFLUSH("unhandle evt %d", p_ble_evt->header.evt_id);
            break;
    }

    if (ok_is_peer_manager_enable()) {
        pm_handler_secure_on_connection(p_ble_evt);
        ok_peer_manager_ble_evt_handler(p_ble_evt);
    }
}

char *ok_ble_adv_name_get(void)
{
    return &ble_adv_name[0];
}

uint16_t ok_ble_gatt_max_mtu_get(void)
{
    return m_ble_gatt_max_data_len;
}

uint16_t ok_ble_conn_handle_get(void)
{
    return m_conn_handle;
}

void ok_ble_gap_local_disconnect(void)
{
    // ble not connect, just return
    if (m_conn_handle == BLE_CONN_HANDLE_INVALID) {
        return;
    }

    ret_code_t err_code = NRF_SUCCESS;
    err_code = sd_ble_gap_disconnect(m_conn_handle, BLE_HCI_LOCAL_HOST_TERMINATED_CONNECTION);
    APP_ERROR_CHECK(err_code);
}

void ok_ble_init(void)
{
    ble_stack_init();
    peer_manager_init();
    gap_params_init();
    gatt_init();
    services_init();
    advertising_init();
    conn_params_init();

    // fmna init
    fmna_app_init();
}
