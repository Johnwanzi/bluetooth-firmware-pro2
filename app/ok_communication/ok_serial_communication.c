#include <stdint.h>
#include <string.h>
#include "app_error.h"
#include "app_timer.h"
#include "app_uart.h"
#include "nordic_common.h"
#include "nrf.h"
#include "sdk_macros.h"
#include "app_scheduler.h"
#include "nrf_delay.h"
#include "nrf_power.h"
#include "nrf_uarte.h"
#include "nrf_gpio.h"
#include "nrfx_gpiote.h"
#include "ble_nus.h"

#include "ok_platform.h"
#include "ok_cmd_protocol.h"

#define RX_PIN_NUMBER    11
#define TX_PIN_NUMBER    12
#define CTS_PIN_NUMBER   UART_PIN_DISCONNECTED
#define RTS_PIN_NUMBER   UART_PIN_DISCONNECTED

#define UART_TX_BUF_SIZE 256
#define UART_RX_BUF_SIZE 256

enum {
    FRAME_START = 0,
    FRAME_SOF_L = 1,
    FRAME_SOF_H = 2,
    FRAME_LEN_L = 3,
    FRAME_LEN_H = 4,
    FRAME_DATA  = 5
};

static volatile bool app_uart_is_initialized = false;

static uint8_t uart_data_array[64];
static uint8_t uart_trans_buff[128];

static uint8_t calcXor(uint8_t *buf, uint8_t len)
{
    uint8_t tmp = 0;
    uint8_t i;

    for (i = 0; i < len; i++) {
        tmp ^= buf[i];
    }
    return tmp;
}

static void uart_event_handle(app_uart_evt_t *p_event)
{
    static uint8_t  index = 0;
    static uint32_t lenth = 0;
    uint8_t         uart_xor_byte;

    if (p_event->evt_type == APP_UART_DATA_READY) {
        UNUSED_VARIABLE(app_uart_get(&uart_data_array[index]));
        index++;

        if (FRAME_SOF_L == index) {
            if (UART_TX_TAG != uart_data_array[0]) {
                index = 0;
                return;
            }
        } else if (FRAME_SOF_H == index) {
            if (UART_TX_TAG2 != uart_data_array[1]) {
                index = 0;
                return;
            }
        } else if (FRAME_LEN_L == index) {
            if ((UART_TX_TAG2 == uart_data_array[0]) && (UART_TX_TAG == uart_data_array[1])) {
                index = 0;
                return;
            }
        } else if (FRAME_LEN_H == index) {
            lenth = ((uint32_t)uart_data_array[2] << 8) + uart_data_array[3];
        } else if (index >= lenth + 4) {
            uart_xor_byte = calcXor(uart_data_array, index - 1);
            if (uart_xor_byte != uart_data_array[index - 1]) {
                index = 0;
                return;
            }

            ok_cmd_parse(&uart_data_array[4], lenth - 1); /* remove xor byte */
        }
    }

    if (p_event->evt_type == APP_UART_COMMUNICATION_ERROR || p_event->evt_type == APP_UART_COMMUNICATION_ERROR) {
        NRF_LOG_INFO("uart error type %d", p_event->evt_type);
    }
}

static void uart_put_data(uint8_t *pdata, uint8_t lenth)
{
    app_uart_put_data(pdata, lenth);
}

static void usr_uart_init(void)
{
    uint32_t                     err_code;
    const app_uart_comm_params_t comm_params = {.rx_pin_no    = RX_PIN_NUMBER,
                                                .tx_pin_no    = TX_PIN_NUMBER,
                                                .rts_pin_no   = RTS_PIN_NUMBER,
                                                .cts_pin_no   = CTS_PIN_NUMBER,
                                                .flow_control = APP_UART_FLOW_CONTROL_DISABLED,
                                                .use_parity   = false,
                                                .baud_rate    = NRF_UARTE_BAUDRATE_115200};

    APP_UART_FIFO_INIT(&comm_params, UART_RX_BUF_SIZE, UART_TX_BUF_SIZE, uart_event_handle, APP_IRQ_PRIORITY_LOWEST, err_code);
    APP_ERROR_CHECK(err_code);
    app_uart_is_initialized = true;
}

void ok_send_stm_data(void *pdata, uint16_t lenth)
{
    uart_trans_buff[0] = UART_TX_TAG2;
    uart_trans_buff[1] = UART_TX_TAG;
    uart_trans_buff[2] = 0x00;
    uart_trans_buff[3] = lenth + 1;
    memcpy(&uart_trans_buff[4], pdata, lenth);
    uart_trans_buff[uart_trans_buff[3] + 3] = calcXor(uart_trans_buff, (uart_trans_buff[3] + 3));

    uart_put_data(uart_trans_buff, uart_trans_buff[3] + 4);
}

void ok_serial_communication_init(void)
{
    usr_uart_init();
}

void ok_serial_communication_deinit(void)
{
    if (!app_uart_is_initialized) {
        return;
    }
    app_uart_close();
    app_uart_is_initialized = false;
}
