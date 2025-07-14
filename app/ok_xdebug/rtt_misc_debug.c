#include <stdint.h>
#include <string.h>
#include "app_error.h"
#include "app_timer.h"
#include "SEGGER_RTT.h"
#include "nrf_delay.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"

#include "ok_device_config.h"
#include "ok_platform.h"

static int ok_scan_rtt_terminal(uint8_t *out, uint8_t len)
{
    if (out == NULL) {
        return 0;
    }

    return SEGGER_RTT_ReadNoLock(0, out, len);
}

void ok_rtt_detect_input(void)
{
    uint8_t data[10] = {0};
    uint8_t len      = 0;
    if (0 == (len = ok_scan_rtt_terminal(data, sizeof(data)))) {
        return;
    }

    switch (data[0]) {
        // flash operation test
        case '0': {
            extern void xdebug_flash_test(void);
            xdebug_flash_test();
        } break;

        // device config test
        case '1': {
            ok_devcfg_t *devcfg = ok_device_config_get();
            ok_device_config_init();

            for (int i = 0; i < 50; i++) {
                devcfg->settings.bt_ctrl = i % 2;
                ok_device_config_commit();
            }
        } break;

        // rtc test
        case '2': {
            uint32_t rtc32 = NRF_RTC1->COUNTER;
            nrf_delay_ms(1000);
            OK_LOG_INFO("Delta ms %d", ((NRF_RTC1->COUNTER - rtc32) * 1000) >> 14);
            nrf_delay_ms(1343);
            OK_LOG_INFO("Delta ms %d", ((NRF_RTC1->COUNTER - rtc32) * 1000) >> 14);
            nrf_delay_ms(5657);
            OK_LOG_INFO("Delta ms %d", ((NRF_RTC1->COUNTER - rtc32) * 1000) >> 14);
        } break;

        default:
            break;
    }
}
