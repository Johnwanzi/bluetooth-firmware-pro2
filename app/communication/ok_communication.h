#ifndef __OK_COMMUNICATION_H__
#define __OK_COMMUNICATION_H__

#include "data_transmission.h"

#define SLAVE_SPI_RSP_IO 13

void ok_serial_communication_init(void);
void ok_serial_communication_deinit(void);
void ok_send_stm_data(void *pdata, uint16_t lenth);


#endif /* __OK_COMMUNICATION_H__ */
