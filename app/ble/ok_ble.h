#ifndef __OK_BLE_H__
#define __OK_BLE_H__

#include "ble_gap.h"
#include "ble.h"
#include "peer_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

/************************************************ dual adv management ************************************************/
#define BLE_INSTANCE_NUM 2 // Number of BLE instances (e.g., Onekey and MFi)

enum {
    BLE_ONEKEY_ADV_E = 0,
    BLE_MFI_ADV_E,
    BLE_ADV_INSTANCE_NUM
};

enum {
    BLE_MANAGE_UPDATE_ADV_DATA = 0,
    BLE_MANAGE_UPDATE_ADV_PARAMS,
    BLE_MANAGE_UPDATE_ADV_TOTAL,
    BLE_MANAGE_UPDATE_MAC_ADDR,
    BLE_MANAGE_UPDATE_EVT_HANDLER,
    BLE_MANAGE_UPDATE_INVALID,
};

typedef struct {
    bool                 adv_alive;
    uint16_t             conn_handle;
    ble_gap_addr_t       mac;
    ble_gap_adv_data_t   adv_data;
    ble_gap_adv_params_t adv_params;
    void (*ble_evt_handler)(ble_evt_t const *p_ble_evt);
} ble_adv_instance_t;

typedef struct {
    uint32_t adv_timeout_ms;
    void    *adv_timer_id;
    void (*adv_timer_handler)(void *p_context);
} ble_adv_timer_t;

typedef struct {
    bool               adv_is_managed;
    bool               adv_is_running;
    uint8_t            adv_alive_num;
    uint8_t            adv_handle;
    ble_adv_timer_t    adv_timer;
    ble_adv_instance_t adv[BLE_INSTANCE_NUM];
} ble_adv_manage_t;

void    ble_adv_manage_init(void);
void    ble_adv_manage_update(uint8_t instance_id, uint8_t data_type, void *data);
void    ble_adv_manage_register(uint8_t instance_id, ble_adv_instance_t *adv_config, bool start_adv_immediately);
void    ble_adv_manage_unregister(uint8_t instance_id, bool stop_adv);
void    ble_adv_manage_event(ble_evt_t const *p_ble_evt);
uint8_t ble_adv_manage_conn_instance_id_get(ble_evt_t const *p_ble_evt);

/************************************************ BLE common functions ************************************************/
void ok_trans_timer_init(void);
void ok_trans_timer_start(void);
void ok_bas_timer_init(void);
void ok_bas_timer_start(void);

void    ok_ble_init(void);
char   *ok_ble_adv_name_get(void);
void    ok_ble_adv_ctrl(uint8_t enable);
void    ok_ble_adv_onoff_set(uint8_t onoff);
uint8_t ok_ble_adv_onoff_get(void);
void    ok_ble_adv_process(void);
void    ok_ble_gap_local_disconnect(void);

void ok_peer_manager_lesc_process(void);
void ok_peer_manage_update(void);

#ifdef __cplusplus
}
#endif

#endif /* __OK_BLE_COMMON_H__ */
