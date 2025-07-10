#include <stdint.h>
#include <string.h>
#include "nordic_common.h"
#include "app_error.h"
#include "nrf_soc.h"
#include "nrf_sdh_soc.h"
#include "nrf_uarte.h"
#include "nrf_gpio.h"
#include "nrfx_gpiote.h"
#include "nrf_pwr_mgmt.h"
#include "nrf_delay.h"

#include "power_manage.h"
#include "peer_manager_handler.h"
#include "ok_cmd_protocol.h"
#include "ok_pwr_manage.h"
#include "ok_communication.h"
#include "ok_platform.h"

#define ST_WAKE_IO 22

static volatile bool pmu_status_synced      = false;
static volatile bool pmu_feat_synced        = false;
static volatile bool pmu_feat_charge_enable = false;

static inline void pmu_status_print()
{
    PMU_t *pmu_p = power_manage_ctx_get();

    NRF_LOG_INFO("=== PowerStatus ===");
    NRF_LOG_INFO("PMIC_IRQ_IO -> %s", (nrf_gpio_pin_read(PMIC_IRQ_IO) ? "HIGH" : "LOW"));
    NRF_LOG_INFO("sysVoltage=%lu", pmu_p->PowerStatus->sysVoltage);
    NRF_LOG_INFO("batteryPresent=%u", pmu_p->PowerStatus->batteryPresent);
    NRF_LOG_INFO("batteryPercent=%u", pmu_p->PowerStatus->batteryPercent);
    NRF_LOG_INFO("batteryVoltage=%lu", pmu_p->PowerStatus->batteryVoltage);
    NRF_LOG_INFO("batteryTemp=%ld", pmu_p->PowerStatus->batteryTemp);
    NRF_LOG_INFO("pmuTemp=%lu", pmu_p->PowerStatus->pmuTemp);
    NRF_LOG_INFO("chargeAllowed=%u", pmu_p->PowerStatus->chargeAllowed);
    NRF_LOG_INFO("chargerAvailable=%u", pmu_p->PowerStatus->chargerAvailable);
    NRF_LOG_INFO("chargeFinished=%u", pmu_p->PowerStatus->chargeFinished);
    NRF_LOG_INFO("wiredCharge=%u", pmu_p->PowerStatus->wiredCharge);
    NRF_LOG_INFO("wirelessCharge=%u", pmu_p->PowerStatus->wirelessCharge);
    NRF_LOG_INFO("chargeCurrent=%lu", pmu_p->PowerStatus->chargeCurrent);
    NRF_LOG_INFO("dischargeCurrent=%lu", pmu_p->PowerStatus->dischargeCurrent);
    NRF_LOG_INFO("irqSnapshot=0x%08x", pmu_p->PowerStatus->irqSnapshot);
    NRF_LOG_INFO("=== ============== ===");
    NRF_LOG_FLUSH();
}

static void pmu_sys_voltage_monitor(void)
{
    static uint8_t match_count    = 0;
    const uint8_t  match_required = 30;
    const uint16_t minimum_mv     = 3300;

    PMU_t *pmu_p = power_manage_ctx_get();

    if ((match_count < match_required)) {
        // not triggered
        if (pmu_p->PowerStatus->batteryVoltage < minimum_mv) {
            // voltage low
            if (pmu_p->PowerStatus->chargerAvailable) {
                // has charger, ignore
                // NRF_LOG_INFO("Low batteryVoltage detect skiped since charger available");
                // reset counter
                match_count = 0;
            } else {
                // increase counter
                match_count++;
                NRF_LOG_INFO("Low batteryVoltage debounce, match %u/%u (batteryVoltage=%lu)", match_count, match_required,
                             pmu_p->PowerStatus->batteryVoltage);
            }
        } else {
            // voltage normal
            if (match_count > 0) {
                // reset counter if not zero
                match_count = 0;
                NRF_LOG_INFO("Low batteryVoltage debounce, match reset");
                NRF_LOG_FLUSH();
            }
        }
    } else {
        // already triggered
        NRF_LOG_INFO("Low batteryVoltage debounce, match fulfilled, force shutdown pmu");
        NRF_LOG_FLUSH();
        pmu_p->SetState(PWR_STATE_HARD_OFF);
    }
}

static void pmu_pwrok_pull()
{
    static uint8_t match_count    = 0;
    const uint8_t  match_required = 10;

    if (!nrf_gpio_pin_read(PMIC_PWROK_IO)) {
        match_count++;
        NRF_LOG_INFO("PowerOK debounce, match %u/%u", match_count, match_required);
    } else {
        if (match_count > 0) {
            match_count = 0;
            NRF_LOG_INFO("PowerOK debounce, match reset");
            NRF_LOG_FLUSH();
        }
    }

    if ((match_count >= match_required)) {
        NRF_LOG_INFO("PowerOK debounce, match fulfilled, entering low power mode");
        NRF_LOG_FLUSH();
        enter_low_power_mode();
    }
}

static void pmu_irq_pull()
{
    PMU_t *pmu_p = power_manage_ctx_get();

    if (!nrf_gpio_pin_read(PMIC_IRQ_IO)) {
        PRINT_CURRENT_LOCATION();

        // wait charger status stabilize before process irq
        // chargerAvailable may take few ms to be set in some case

        Power_Status_t pwr_status_temp = {0};
        uint8_t        match_count     = 0;
        const uint8_t  match_required  = 3;
        while (match_count < match_required) {
            pmu_p->PullStatus();

            if ((pwr_status_temp.chargerAvailable == pmu_p->PowerStatus->chargerAvailable) &&
                (pwr_status_temp.wiredCharge == pmu_p->PowerStatus->wiredCharge) &&
                (pwr_status_temp.wirelessCharge == pmu_p->PowerStatus->wirelessCharge)) {
                match_count++;
                NRF_LOG_INFO("PowerStatus debounce, match %u/%u", match_count, match_required);

                continue;
            } else {
                match_count = 0;
                NRF_LOG_INFO("PowerStatus debounce, match reset");

                pwr_status_temp.chargerAvailable = pmu_p->PowerStatus->chargerAvailable;
                pwr_status_temp.wiredCharge      = pmu_p->PowerStatus->wiredCharge;
                pwr_status_temp.wirelessCharge   = pmu_p->PowerStatus->wirelessCharge;
                nrf_delay_ms(10);
            }
        }
        pmu_status_synced = true;
        pmu_status_print();
        pmu_p->Irq();
    }
}

static void pmu_status_refresh()
{
    PMU_t *pmu_p = power_manage_ctx_get();

    if (pmu_status_synced) {
        return;
    }

    PRINT_CURRENT_LOCATION();
    pmu_p->PullStatus();
    pmu_status_synced = true;
    pmu_status_print();
}

static void pmu_req_process()
{
    PMU_t *pmu_p = power_manage_ctx_get();

    // features control
    if (!pmu_feat_synced) {
        PRINT_CURRENT_LOCATION();
        if (pmu_feat_charge_enable) {
            pmu_p->SetFeature(PWR_FEAT_CHARGE, true); // enable charge
        } else {
            pmu_p->SetFeature(PWR_FEAT_CHARGE, false); // disable charge
        }

        pmu_feat_synced = true;
    }
}

// sdh_soc_handler, mainly for power warning, no other event processed yet
static void sdh_soc_handler(uint32_t sys_evt, void *p_context)
{
    UNUSED_VAR(p_context);

    PMU_t *pmu_p = power_manage_ctx_get();

    if (sys_evt == NRF_EVT_POWER_FAILURE_WARNING) {
        NRF_LOG_INFO("NRF Power POF triggered!");
        NRF_LOG_FLUSH();

        pmu_p->SetState(PWR_STATE_HARD_OFF);
        enter_low_power_mode();
    }
}
NRF_SDH_SOC_OBSERVER(m_soc_observer, 0, sdh_soc_handler, NULL);

/**@brief Handler for shutdown preparation.
 *
 * @details During shutdown procedures, this function will be called at a 1 second interval
 *          untill the function returns true. When the function returns true, it means that the
 *          app is ready to reset to DFU mode.
 *
 * @param[in]   event   Power manager event.
 *
 * @retval  True if shutdown is allowed by this power manager handler, otherwise false.
 */
static bool app_shutdown_handler(nrf_pwr_mgmt_evt_t event)
{
    NRF_LOG_DEBUG("%s , nrf_pwr_mgmt_evt_t = %d", __func__, event);
    NRF_LOG_FLUSH();

    switch (event) {
        case NRF_PWR_MGMT_EVT_PREPARE_WAKEUP:
            // enable wakeup
            nrf_gpio_cfg_sense_input(PMIC_PWROK_IO, NRF_GPIO_PIN_NOPULL, NRF_GPIO_PIN_SENSE_HIGH);
            return true;

        case NRF_PWR_MGMT_EVT_PREPARE_RESET:
            return true;

        case NRF_PWR_MGMT_EVT_PREPARE_DFU:
        case NRF_PWR_MGMT_EVT_PREPARE_SYSOFF:
        default:
            return false;
    }
}
NRF_PWR_MGMT_HANDLER_REGISTER(app_shutdown_handler, 0);

void enter_low_power_mode(void)
{
    PMU_t *pmu_p = power_manage_ctx_get();

    // stop uart/spi
    ok_serial_communication_deinit();
    usr_spi_disable();

    // stop bt adv
    // TODO1K

    // release pmu interface
    if ((pmu_p != NULL) && (pmu_p->isInitialized)) {
        pmu_p->Deinit();
    }

    // release gpio
    nrfx_gpiote_uninit();
    nrf_gpio_cfg_default(ST_WAKE_IO);

    // shutdown
    nrf_pwr_mgmt_shutdown(NRF_PWR_MGMT_SHUTDOWN_GOTO_SYSOFF);
}

void ok_battery_level_sync(void)
{
    uint8_t        bak_buff[2]     = {0};
    static uint8_t bak_bat_persent = 0x00;
    PMU_t         *pmu_p           = power_manage_ctx_get();

    if (bak_bat_persent != pmu_p->PowerStatus->batteryPercent) {
        bak_bat_persent = pmu_p->PowerStatus->batteryPercent;
        bak_buff[0]     = OK_DOWNLINK_MAIN_CMD_POWER_PERCENT;
        bak_buff[1]     = pmu_p->PowerStatus->batteryPercent;
        ok_send_stm_data(bak_buff, 2);
    }
}

void ok_pmu_sche_process(void)
{
    pmu_sys_voltage_monitor();
    pmu_pwrok_pull();
    pmu_irq_pull();
    pmu_status_refresh();
    pmu_req_process();
}

// 1-enable 0-disable
void ok_pmu_charge_ctrl(uint8_t enable)
{
    pmu_feat_charge_enable = enable;
    pmu_feat_synced        = false;
}

void ok_pmu_wakeup_peer_device(void)
{
    PMU_t *pmu_p = power_manage_ctx_get();
    if (pmu_p) {
        pmu_p->SetState(PWR_STATE_ON);
    }
}

// Onekey hardware power management initialization
void ok_pmu_init(void)
{
#define PMU_WAKEUP_RETRY_COUNT 10

    set_send_stm_data_p(ok_send_stm_data);

    int i;
    for (i = 0; i < PMU_WAKEUP_RETRY_COUNT; i++) {
        if (power_manage_init() && (power_manage_ctx_get() != NULL && power_manage_ctx_get()->isInitialized)) {
            OK_LOG_INFO("PMU Init Success");
            break;
        }
        OK_LOG_INFO("Trying %d times...", i + 1);
        nrf_delay_ms(10);
    }

    if (i == PMU_WAKEUP_RETRY_COUNT) {
        OK_LOG_WARN("PMU Init Fail");
        enter_low_power_mode();
    }
}
