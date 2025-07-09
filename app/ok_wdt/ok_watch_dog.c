#include <stdint.h>
#include "nrf_sdh.h"
#include "nrf_drv_wdt.h"
#include "app_timer.h"

#include "ok_ble.h"
#include "ok_platform.h"

APP_TIMER_DEF(m_wdt_timer_id);

static nrf_drv_wdt_channel_id m_channel_id;
static uint8_t m_wdt_enable = 0;

static void m_wdt_event_handler(void)
{
    NRF_LOG_INFO("WDT Triggered!");
    NRF_LOG_FLUSH();
}

static void m_wdt_feed_hander(void *p_context)
{
    UNUSED_PARAMETER(p_context);

    if (m_wdt_enable) {
        nrf_drv_wdt_channel_feed(m_channel_id);
    }
}

void ok_wdt_timer_init(void)
{
    ret_code_t err_code;
    err_code = app_timer_create(&m_wdt_timer_id, APP_TIMER_MODE_REPEATED, m_wdt_feed_hander);
    APP_ERROR_CHECK(err_code);
}

void ok_wdt_timer_start(void)
{
    ret_code_t err_code;
    err_code = app_timer_start(m_wdt_timer_id, APP_TIMER_TICKS(1000), NULL);
    APP_ERROR_CHECK(err_code);
}

void ok_watch_dog_init(void)
{
    uint32_t             err_code = NRF_SUCCESS;
    nrf_drv_wdt_config_t config   = NRF_DRV_WDT_DEAFULT_CONFIG;
    err_code                      = nrf_drv_wdt_init(&config, m_wdt_event_handler);
    APP_ERROR_CHECK(err_code);
    err_code = nrf_drv_wdt_channel_alloc(&m_channel_id);
    APP_ERROR_CHECK(err_code);
    nrf_drv_wdt_enable();
    m_wdt_enable = 1;
}
