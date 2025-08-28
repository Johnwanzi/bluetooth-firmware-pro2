#include <stdint.h>
#include "fmna_platform_includes.h"
#include "fmna_version.h"
#include "fmna_malloc_platform.h"
#include "fmna_gatt.h"
#include "fmna_adv.h"
#include "fmna_connection.h"
#include "fmna_crypto.h"
#include "fmna_motion_detection.h"
#include "fmna_state_machine.h"
#include "fmna_storage.h"
#include "fmna_app.h"

static void fmna_adv_init(void) 
{
    ble_adv_manage_register(BLE_MFI_ADV_E, NULL, false);
    ble_adv_manage_update(BLE_MFI_ADV_E, BLE_MANAGE_UPDATE_EVT_HANDLER, fmna_ble_peripheral_evt);
    fmna_adv_reset_bd_addr();
}

void fmna_app_init(void)
{
    // platform init
    fmna_version_init();
    fmna_malloc_platform_init();
    fmna_storage_init();
    fmna_gatt_services_init();

    fmna_adv_init();

    // app init
    fmna_connection_init();
    fmna_crypto_init();
    fmna_motion_detection_init();
    fmna_state_machine_init();
}
