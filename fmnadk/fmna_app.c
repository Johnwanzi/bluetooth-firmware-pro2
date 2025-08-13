#include <stdint.h>
#include "fmna_platform_includes.h"
#include "fmna_version.h"
#include "fmna_malloc_platform.h"
#include "fmna_gatt.h"
#include "fmna_connection.h"
#include "fmna_crypto.h"
#include "fmna_motion_detection.h"
#include "fmna_state_machine.h"
#include "fmna_storage.h"
#include "fmna_app.h"

void fmna_app_init(void)
{
    // platform init
    fmna_version_init();
    fmna_malloc_platform_init();
    fmna_storage_init();
    fmna_gatt_services_init();

    // app init
    fmna_connection_init();
    fmna_crypto_init();
    fmna_motion_detection_init();
    fmna_state_machine_init();
}
