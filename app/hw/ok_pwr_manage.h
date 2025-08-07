#ifndef __OK_PWR_MANAGE_H__
#define __OK_PWR_MANAGE_H__

#include "power_manage.h"

void enter_low_power_mode(void);
void ok_battery_level_sync(void);
void ok_pmu_charge_ctrl(uint8_t enable);
void ok_pmu_sche_process(void);
void ok_pmu_wakeup_peer_device(void);
void ok_pmu_init(void);

#endif //__OK_PWR_MANAGE_H__
