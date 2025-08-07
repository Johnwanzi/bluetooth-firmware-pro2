#include <stdint.h>
#include <string.h>
#include "nrf_fstorage.h"
#include "nrf_fstorage_sd.h"
#include "nrf_fstorage_nvmc.h"
#include "crc32.h"

#include "ok_storage.h"
#include "ok_platform.h"

#define ALIGN_UP(val, align) (((val) + ((align) - 1)) & ~((align) - 1))

static uint8_t flash_buf[512];

// storage format: data + crc32
static bool is_all_ff(uint8_t *buf, uint16_t len)
{
    for (int i = 0; i < len; i++) {
        if (0xff != buf[i]) {
            return false;
        }
    }
    return true;
}

int ok_flash_read(ok_item_storage_t *item)
{
    uint8_t  data_loaded = 0;
    int      ret         = OK_FLASH_SUCCESS;
    uint32_t read_addr   = 0;
    uint32_t flash_size  = 0;

    if (item == NULL || !item->init || item->item_data == NULL || item->p_fs == NULL) {
        OK_LOG_ERROR("ok_storage_init: invalid param");
        return OK_FLASH_PARAM_ERROR;
    }

    // data length + crc32
    uint16_t align_len = ALIGN_UP(item->item_size + 4, FLASH_ALIGN_SIZE);

    if (align_len > sizeof(flash_buf)) {
        OK_LOG_WARN("item_size too large, please enlarge space.");
        return OK_FLASH_SPACE_NOT_ENOUGH;
    }

    flash_size = item->p_fs->end_addr - item->p_fs->start_addr + 1;
    read_addr  = item->p_fs->start_addr;

    for (int i = 0; i < flash_size / align_len; i++) {
        ret_code_t err_code = nrf_fstorage_read(item->p_fs, read_addr, flash_buf, item->item_size + 4);
        if (err_code != NRF_SUCCESS) {
            OK_LOG_ERROR("read flash error");
            ret = OK_FLASH_OPERATION_FAIL;
            break;
        }

        if (is_all_ff(flash_buf, item->item_size)) {
            ret = OK_FLASH_DATA_EMPTY;
            break;
        }

        uint32_t crc      = crc32_compute(flash_buf, item->item_size, NULL);
        uint32_t crc_read = *(uint32_t *)(flash_buf + item->item_size);
        if (crc != crc_read) {
            OK_LOG_WARN("read data crc error.");
            ret = OK_FLASH_CRC_ERROR;
        } else {
            data_loaded = 1;
            memcpy(item->item_data, flash_buf, item->item_size);
        }

        read_addr += align_len;
    }

    return data_loaded ? OK_FLASH_SUCCESS : ret;
}

int ok_flash_write(ok_item_storage_t *item)
{
    uint8_t    page_num   = 0;
    uint32_t   write_addr = 0;
    uint32_t   flash_size = 0;
    ret_code_t err_code   = 0;

    if (item == NULL || item->item_data == NULL || item->p_fs == NULL) {
        OK_LOG_ERROR("ok_flash_write: invalid param");
        return OK_FLASH_PARAM_ERROR;
    }

    // data length + crc32
    uint16_t align_len = ALIGN_UP(item->item_size + 4, FLASH_ALIGN_SIZE);

    if (align_len > sizeof(flash_buf)) {
        OK_LOG_WARN("item_size too large, please enlarge space.");
        return OK_FLASH_SPACE_NOT_ENOUGH;
    }

    if (!item->init) {
        item->init = true;
        nrf_fstorage_init(item->p_fs, &nrf_fstorage_sd, NULL);
    }

    flash_size = item->p_fs->end_addr - item->p_fs->start_addr + 1;
    write_addr = item->p_fs->start_addr;
    page_num   = flash_size / FLASH_PAGE_SIZE;

    int i;
    for (i = 0; i < flash_size / align_len; i++) {
        err_code = nrf_fstorage_read(item->p_fs, write_addr, flash_buf, item->item_size + 4);
        if (err_code != NRF_SUCCESS) {
            OK_LOG_ERROR("read flash error");
            return OK_FLASH_OPERATION_FAIL;
        }

        if (is_all_ff(flash_buf, item->item_size)) {
            memset(flash_buf, 0x00, sizeof(flash_buf));
            memcpy(flash_buf, item->item_data, item->item_size);
            *(uint32_t *)(flash_buf + item->item_size) = crc32_compute(item->item_data, item->item_size, NULL);
            break;
        }

        write_addr += align_len;
    }

    // flash sector full, erase sector
    if (i == flash_size / align_len) {
        err_code = nrf_fstorage_erase(item->p_fs, item->p_fs->start_addr, page_num, NULL);
        if (err_code == NRF_SUCCESS) {
            while (nrf_fstorage_is_busy(item->p_fs)) {
            }
        }
        write_addr = item->p_fs->start_addr;
    }

    // update data to flash
    err_code = nrf_fstorage_write(item->p_fs, write_addr, flash_buf, align_len, NULL);
    if (err_code == NRF_SUCCESS) {
        while (nrf_fstorage_is_busy(item->p_fs)) {
        }
    }

    return OK_FLASH_SUCCESS;
}

void ok_storage_init(ok_item_storage_t *item)
{
    if (item == NULL || item->item_data == NULL || item->p_fs == NULL) {
        OK_LOG_ERROR("ok_storage_init: invalid param");
        return;
    }

    if (!item->init) {
        item->init = true;
        nrf_fstorage_init(item->p_fs, &nrf_fstorage_sd, NULL);
    }

    ok_flash_read(item);
}
