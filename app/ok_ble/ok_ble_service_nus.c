#include <stdint.h>
#include "ble.h"
#include "ble_conn_params.h"
#include "nrf_sdh.h"
#include "nrf_sdh_soc.h"
#include "nrf_sdh_ble.h"
#include "nrf_ble_gatt.h"
#include "nrf_ble_qwr.h"
#include "ble_nus.h"
#include "app_timer.h"
#include "app_scheduler.h"

#include "data_transmission.h"
#include "ok_ble_internal.h"
#include "ok_platform.h"

// DATA FLAG
#define DATA_INIT                 0x00
#define DATA_HEAD                 0x01
#define DATA_RECV                 0x02
#define DATA_WAIT                 0x03

#define RCV_DATA_TIMEOUT_INTERVAL APP_TIMER_TICKS(500)

BLE_NUS_DEF(m_nus, NRF_SDH_BLE_TOTAL_LINK_COUNT);
APP_TIMER_DEF(data_wait_timer_id);


static uint8_t           rcv_head_flag = 0;
static uint8_t          *ble_nus_send_buf;
static volatile uint16_t ble_nus_send_len = 0, ble_nus_send_offset = 0;

static void data_wait_timeout_hander(void *p_context)
{
    UNUSED_PARAMETER(p_context);

    if (rcv_head_flag == DATA_RECV) {
        rcv_head_flag = DATA_WAIT;
    } else if (rcv_head_flag == DATA_WAIT) {
        rcv_head_flag = DATA_INIT;
    }
    spi_state_update();
}

static void ble_nus_send_packet(uint8_t *data, uint16_t data_len)
{
    ret_code_t err_code;
    uint16_t   length       = 0;
    uint16_t   max_mtu_size = ok_ble_gatt_max_mtu_get();
    uint16_t   conn_handle  = ok_ble_conn_handle_get();

    do {
        length   = data_len > max_mtu_size ? max_mtu_size : data_len;
        err_code = ble_nus_data_send(&m_nus, data, &length, conn_handle);
        if ((err_code != NRF_ERROR_INVALID_STATE) && (err_code != NRF_ERROR_RESOURCES) && (err_code != NRF_ERROR_NOT_FOUND)) {
            APP_ERROR_CHECK(err_code);
        }
    } while (err_code == NRF_ERROR_RESOURCES);
}

/**@brief Function for handling the data from the Nordic UART Service.
 *
 * @details This function will process the data received from the Nordic UART BLE Service and send
 *          it to the UART module.
 *
 * @param[in] p_evt       Nordic UART Service event.
 */
/**@snippet [Handling the data received over BLE] */
static void nus_data_handler(ble_nus_evt_t *p_evt)
{
    uint32_t pad          = 0;
    uint32_t nus_data_len = 0;
    uint16_t max_mtu_size = ok_ble_gatt_max_mtu_get();

    static uint32_t msg_len;

    uint8_t nus_data_buf[NRF_SDH_BLE_GATT_MAX_MTU_SIZE - OPCODE_LENGTH - HANDLE_LENGTH] = {0};


    NRF_LOG_INFO("enter nus_data_handler, type %d.", p_evt->type);

    if (p_evt->type == BLE_NUS_EVT_RX_DATA) {
        NRF_LOG_INFO("Received data from BLE NUS.");
        NRF_LOG_HEXDUMP_DEBUG(p_evt->params.rx_data.p_data, p_evt->params.rx_data.length);
        nus_data_len = p_evt->params.rx_data.length;
        memcpy(nus_data_buf, (uint8_t *)p_evt->params.rx_data.p_data, nus_data_len);

        if (rcv_head_flag == DATA_INIT) {
            if (nus_data_buf[0] == '?' && nus_data_buf[1] == '#' && nus_data_buf[2] == '#') {
                if (nus_data_len < 9) {
                    return;
                } else {
                    msg_len = (uint32_t)((nus_data_buf[5] << 24) + (nus_data_buf[6] << 16) + (nus_data_buf[7] << 8) + (nus_data_buf[8]));
                    pad     = ((nus_data_len + 63) / 64) + 8;
                    if (msg_len > nus_data_len - pad) {
                        msg_len -= nus_data_len - pad;
                        rcv_head_flag = DATA_RECV;
                    }
                }
            } else if (nus_data_buf[0] == 0x5A && nus_data_buf[1] == 0xA5 && nus_data_buf[2] == 0x07 && nus_data_buf[3] == 0x1 &&
                       nus_data_buf[4] == 0x03) {
                ok_ble_adv_onoff_set(0);
                return;
            }
        } else {
            if (nus_data_buf[0] == '?') {
                pad = (nus_data_len + 63) / 64;
                if (nus_data_len - pad > msg_len) {
                    rcv_head_flag = DATA_INIT;
                    nus_data_len  = msg_len + (msg_len + 62) / 63;
                    msg_len       = 0;
                } else {
                    msg_len -= nus_data_len - pad;
                    rcv_head_flag = DATA_RECV;
                }
            } else {
                rcv_head_flag = DATA_INIT;
            }
        }
        // spi_write_st_data(nus_data_buf, nus_data_len);
        app_sched_event_put(nus_data_buf, nus_data_len, spi_write_st_data);
    } else if (p_evt->type == BLE_NUS_EVT_TX_RDY) {
        uint32_t length = 0;

        length = ble_nus_send_len - ble_nus_send_offset;
        if (length > 0) {
            length = length > max_mtu_size ? max_mtu_size : length;
            ble_nus_send_packet(ble_nus_send_buf + ble_nus_send_offset, length);
            ble_nus_send_offset += length;
        } else {
            ble_nus_send_len    = 0;
            ble_nus_send_offset = 0;
        }
    }
}

void ble_nus_send(uint8_t *data, uint16_t len)
{
    uint16_t length       = 0;
    uint16_t max_mtu_size = ok_ble_gatt_max_mtu_get();
    uint16_t conn_handle  = ok_ble_conn_handle_get();

    NRF_LOG_INFO("ble_nus_send_len: %d", len);

    if (conn_handle == BLE_CONN_HANDLE_INVALID) {
        return;
    }

    ble_nus_send_buf = data;
    ble_nus_send_len = len;

    length              = len > max_mtu_size ? max_mtu_size : len;
    ble_nus_send_offset = length;
    ble_nus_send_packet(data, length);
}

void ok_trans_timer_init(void)
{
    ret_code_t err_code;
    err_code = app_timer_create(&data_wait_timer_id, APP_TIMER_MODE_REPEATED, data_wait_timeout_hander);
    APP_ERROR_CHECK(err_code);
}

void ok_trans_timer_start(void)
{
    ret_code_t err_code;
    err_code = app_timer_start(data_wait_timer_id, RCV_DATA_TIMEOUT_INTERVAL, NULL);
    APP_ERROR_CHECK(err_code);
}

// data transmission service init
void ok_trans_service_init(void)
{
    uint32_t       err_code;
    ble_nus_init_t nus_init = {0};

    // Initialize Data Transmission Service.
    memset(&nus_init, 0, sizeof(nus_init));
    nus_init.data_handler = nus_data_handler;
    err_code              = ble_nus_init(&m_nus, &nus_init);
    APP_ERROR_CHECK(err_code);
}
