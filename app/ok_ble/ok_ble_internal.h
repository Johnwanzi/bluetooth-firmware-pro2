#ifndef __OK_BLE_INTERNAL_H__
#define __OK_BLE_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "ok_ble.h"

#define APP_BLE_OBSERVER_PRIO 3 /**< Application's BLE observer priority. You shouldn't need to modify this value. */
#define APP_BLE_CONN_CFG_TAG  1 /**< A tag identifying the SoftDevice BLE configuration. */

// service
void ok_dev_info_service_init(void);
void ok_bas_service_init(void);
void ok_trans_service_init(void);
void ok_fido_service_init(void);

void ok_ble_adv_init(void);

void ok_peer_manager_init(void);
bool ok_is_peer_manager_enable(void);
void ok_peer_manager_ble_evt_handler(const ble_evt_t *p_ble_evt);

uint16_t ok_ble_gatt_max_mtu_get(void);
uint16_t ok_ble_conn_handle_get(void);

#ifdef __cplusplus
}
#endif

#endif /* __OK_BLE_COMMON_H__ */
