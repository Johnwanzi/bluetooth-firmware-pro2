/**
 * Copyright (c) 2014 - 2019, Nordic Semiconductor ASA
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form, except as embedded into a Nordic
 *    Semiconductor ASA integrated circuit in a product or a software update for
 *    such product, must reproduce the above copyright notice, this list of
 *    conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of Nordic Semiconductor ASA nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * 4. This software, with or without modification, must only be used with a
 *    Nordic Semiconductor ASA integrated circuit.
 *
 * 5. Any software provided in binary form under this license must not be reverse
 *    engineered, decompiled, modified and/or disassembled.
 *
 * THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
/** @file
 *
 * @defgroup ble_sdk_uart_over_ble_main main.c
 * @{
 * @ingroup  ble_sdk_app_nus_eval
 * @brief    UART over BLE application main file.
 *
 * This file contains the source code for a sample application that uses the Nordic UART service.
 * This application uses the @ref srvlib_conn_params module.
 */

#include <stdint.h>
#include <string.h>
#include "app_error.h"
#include "app_timer.h"
#include "app_uart.h"
#include "ble_advdata.h"
#include "ble_advertising.h"
#include "ble_bas.h"
#include "ble_conn_params.h"
#include "ble_conn_state.h"
#include "ble_dis.h"
#include "ble_hci.h"
#include "ble_nus.h"
#include "ble_fido.h"
#include "nordic_common.h"
#include "nrf.h"
#include "nrf_ble_gatt.h"
#include "nrf_ble_lesc.h"
#include "nrf_ble_qwr.h"
#include "nrf_drv_saadc.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
#include "nrf_pwr_mgmt.h"
#include "nrf_sdh.h"
#include "nrf_sdh_ble.h"
#include "nrf_sdh_soc.h"
#include "peer_manager.h"
#include "peer_manager_handler.h"
#include "sdk_macros.h"
#include "app_scheduler.h"
#include "nrf_bootloader_info.h"
#include "nrf_crypto.h"
#include "nrf_crypto_init.h"
#include "nrf_delay.h"
#include "nrf_drv_wdt.h"
#include "nrf_power.h"
#include "nrf_uarte.h"
#include "nrf_gpio.h"
#include "nrfx_gpiote.h"

#include "util_macros.h"
#include "firmware_config.h"

#include "ok_platform.h"
#include "ok_ble.h"
#include "ok_pwr_manage.h"
#include "ok_communication.h"
#include "ok_flashled.h"
#include "ok_watch_dog.h"

#define SCHED_MAX_EVENT_DATA_SIZE   256 //!< Maximum size of the scheduler event data.
#define SCHED_QUEUE_SIZE            10   //!< Size of the scheduler queue.

static void in_gpiote_handler(nrfx_gpiote_pin_t pin, nrf_gpiote_polarity_t action);

/***********************************************************************************************
|                                    Nordic native interface                                   |
************************************************************************************************/
static uint32_t get_rtc_counter(void)
{
    return NRF_RTC1->COUNTER;
}

// Function for initializing the nrf log module.
static void log_init(void)
{
    ret_code_t err_code = NRF_LOG_INIT(get_rtc_counter);
    APP_ERROR_CHECK(err_code);

    NRF_LOG_DEFAULT_BACKENDS_INIT();
}

// Function for initializing gpio for PMIC and GPIOTE
static void gpio_init(void)
{
    ret_code_t err_code;

    err_code = nrfx_gpiote_init();
    APP_ERROR_CHECK(err_code);

    nrfx_gpiote_in_config_t in_config = NRFX_GPIOTE_CONFIG_IN_SENSE_HITOLO(true);
    in_config.pull                    = NRF_GPIO_PIN_PULLUP;
    err_code                          = nrfx_gpiote_in_init(SLAVE_SPI_RSP_IO, &in_config, in_gpiote_handler);
    APP_ERROR_CHECK(err_code);
    nrfx_gpiote_in_event_enable(SLAVE_SPI_RSP_IO, true);

    nrf_gpio_cfg_input(PMIC_PWROK_IO, NRF_GPIO_PIN_NOPULL);
    nrf_gpio_cfg_input(PMIC_IRQ_IO, NRF_GPIO_PIN_PULLUP);
}

// Function for initializing power management
static void power_management_init(void)
{
    ret_code_t err_code = nrf_pwr_mgmt_init();
    APP_ERROR_CHECK(err_code);
}

// Function for initializing timer module
static void timers_init(void)
{
    ret_code_t err_code;

    // Initialize timer module.
    err_code = app_timer_init();
    APP_ERROR_CHECK(err_code);

    // Create timers.
    ok_bas_timer_init();
    ok_trans_timer_init();
    ok_wdt_timer_init();
}

// Function for initializing scheduler.
static void scheduler_init(void)
{
    APP_SCHED_INIT(SCHED_MAX_EVENT_DATA_SIZE, SCHED_QUEUE_SIZE);
}

/***********************************************************************************************
|                                  Onekey funtion initialization                                |
************************************************************************************************/
// spi read notification
static void in_gpiote_handler(nrfx_gpiote_pin_t pin, nrf_gpiote_polarity_t action)
{
    switch (pin) {
        case SLAVE_SPI_RSP_IO:
            OK_LOG_INFO("GPIO IRQ -> SLAVE_SPI_RSP_IO");
            if (spi_dir_out) {
                spi_dir_out = false;
            } else if (nrf_gpio_pin_read(SLAVE_SPI_RSP_IO) == 0 && !spi_dir_out) {
                app_sched_event_put(NULL, 0, spi_read_st_data);
            }
            break;
        default:
            break;
    }
}

static void ok_periph_init(void)
{
    OK_LOG_INFO("Onekey Peripherals Init.");

    timers_init();
    usr_spim_init();
    ok_serial_communication_init();
    ok_pmu_wakeup_peer_device();
    set_led_brightness(0);
}

static void ok_power_mode_config(void)
{
    ret_code_t err_code = NRF_SUCCESS;

    OK_LOG_INFO("enter ok_power_mode_config.");

    do {
        err_code = sd_power_dcdc_mode_set(NRF_POWER_DCDC_ENABLE);
        if (err_code != NRF_SUCCESS) {
            OK_LOG_INFO("NRF Power enable DCDC failed");
            break;
        }

        err_code = sd_power_pof_threshold_set(NRF_POWER_THRESHOLD_V28);
        if (err_code != NRF_SUCCESS) {
            OK_LOG_INFO("NRF Power set POF threadhold failed");
            break;
        }

        err_code = sd_power_pof_enable(true);
        if (err_code != NRF_SUCCESS) {
            OK_LOG_INFO("NRF Power enable POF failed");
            break;
        }
    } while (0);

    if (err_code != NRF_SUCCESS) {
        enter_low_power_mode();
    }
}

static void ok_app_timers_start(void)
{
    ok_bas_timer_start();
    ok_trans_timer_start();
    ok_wdt_timer_start();
}

static void idle_state_handle(void)
{
    if (NRF_LOG_PROCESS() == false) {
        nrf_pwr_mgmt_run();
    }
}

int main(void)
{
    log_init();
    gpio_init();
    power_management_init();
    nrf_crypto_init(); // why here

    ok_pmu_init();
    ok_device_config_init();
    ok_periph_init();
    ok_ble_init();

    scheduler_init();

    ok_power_mode_config();
    ok_app_timers_start();
    ok_watch_dog_init();

    OK_LOG_INFO("Main Loop Start");

    for (;;) {
        ok_ble_adv_process();
        app_sched_execute();
        ok_pmu_sche_process();
        ok_battery_level_sync();
        ok_peer_manager_lesc_process();     
        idle_state_handle();

        #if RTT_DEBUG_ENABLE
        void ok_rtt_detect_input(void);
        ok_rtt_detect_input();
        #endif
    }
}
/**
 * @}
 */