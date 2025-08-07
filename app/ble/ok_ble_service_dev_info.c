#include <stdint.h>
#include "ble.h"
#include "ble_conn_params.h"
#include "nrf_sdh.h"
#include "nrf_sdh_soc.h"
#include "nrf_sdh_ble.h"
#include "nrf_ble_gatt.h"
#include "ble_dis.h"
#include "app_timer.h"

#include "firmware_config.h"
#include "ok_ble_internal.h"
#include "ok_platform.h"

// Initialize Device Information Service.
void ok_dev_info_service_init(void)
{
    uint32_t       err_code;
    ble_dis_init_t dis_init = {0};

    memset(&dis_init, 0, sizeof(dis_init));

    ble_srv_ascii_to_utf8(&dis_init.manufact_name_str, MANUFACTURER_NAME);
    ble_srv_ascii_to_utf8(&dis_init.model_num_str, ok_ble_adv_name_get());
    ble_srv_ascii_to_utf8(&dis_init.serial_num_str, MODEL_NUMBER);
    ble_srv_ascii_to_utf8(&dis_init.hw_rev_str, HW_REVISION);
    ble_srv_ascii_to_utf8(&dis_init.fw_rev_str, FW_REVISION);
    ble_srv_ascii_to_utf8(&dis_init.sw_rev_str, SW_REVISION);

    ble_dis_sys_id_t system_id;
    system_id.manufacturer_id            = MANUFACTURER_ID;
    system_id.organizationally_unique_id = ORG_UNIQUE_ID;
    dis_init.p_sys_id                    = &system_id;

    dis_init.dis_char_rd_sec = SEC_OPEN;

    err_code = ble_dis_init(&dis_init);
    APP_ERROR_CHECK(err_code);
}
