#ifndef __OK_BLE_H__
#define __OK_BLE_H__

#ifdef __cplusplus
extern "C" {
#endif

void ok_trans_timer_init(void);
void ok_trans_timer_start(void);
void ok_bas_timer_init(void);
void ok_bas_timer_start(void);

void    ok_ble_init(void);
char   *ok_ble_adv_name_get(void);
void    ok_ble_adv_ctrl(uint8_t enable);
void    ok_ble_adv_onoff_set(uint8_t onoff);
uint8_t ok_ble_adv_onoff_get(void);
void    ok_ble_gap_local_disconnect(void);

void    ok_peer_manager_lesc_process(void);

#ifdef __cplusplus
}
#endif

#endif /* __OK_BLE_COMMON_H__ */
