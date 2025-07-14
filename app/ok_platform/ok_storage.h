#ifndef __OK_STORAGE_H__
#define __OK_STORAGE_H__

#include <stdint.h>
#include <stdbool.h>
#include "nrf_fstorage.h"

#define FLASH_ALIGN_SIZE 4
#define FLASH_PAGE_SIZE  4096

enum {
    OK_FLASH_SUCCESS          = 0,
    OK_FLASH_DATA_EMPTY       = -1,
    OK_FLASH_CRC_ERROR        = -2,
    OK_FLASH_OPERATION_FAIL   = -3,
    OK_FLASH_PARAM_ERROR      = -4,
    OK_FLASH_SPACE_NOT_ENOUGH = -5,
};

typedef struct {
    bool            init;
    uint16_t        item_size;
    void           *item_data;
    nrf_fstorage_t *p_fs;
} ok_item_storage_t;

int  ok_flash_read(ok_item_storage_t *item);
int  ok_flash_write(ok_item_storage_t *item);
void ok_storage_init(ok_item_storage_t *item);

#endif // __OK_STORAGE_H__
