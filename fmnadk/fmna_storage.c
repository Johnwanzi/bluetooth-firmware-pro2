#include <stdint.h>
#include <string.h>
#include "nrf_fstorage.h"
#include "nrf_fstorage_sd.h"
#include "nrf_fstorage_nvmc.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
#include "nvs_def.h"
#include "nvs.h"
#include "fmna_storage.h"

const struct nvs_flash_dev fmna_nvs_flash;

static void fmna_nvs_data_evt_handler(nrf_fstorage_evt_t *p_evt)
{
    if (p_evt->result != NRF_SUCCESS) {
        NRF_LOG_INFO("--> Event received: ERROR while executing an fstorage operation.");
        return;
    }

    switch (p_evt->id) {
        case NRF_FSTORAGE_EVT_WRITE_RESULT:
            NRF_LOG_INFO("--> Write event: %d bytes at address 0x%x.", p_evt->len, p_evt->addr);
            break;
        case NRF_FSTORAGE_EVT_ERASE_RESULT:
            NRF_LOG_INFO("--> Erase event: %d page from address 0x%x.", p_evt->len, p_evt->addr);
            break;
        default:
            NRF_LOG_INFO("--> Event received: other event");
            break;
    }
}

NRF_FSTORAGE_DEF(nrf_fstorage_t fmna_nvs_fstorage) = {
    .evt_handler = fmna_nvs_data_evt_handler,
    .start_addr  = FSTORAGE_FMNA_NVS_START_ADDR,
    .end_addr    = FSTORAGE_FMNA_NVS_END_ADDR,
};

static int fmna_nvs_init(void)
{
    nrf_fstorage_init(&fmna_nvs_fstorage, &nrf_fstorage_sd, NULL);
    return 0;
}

static int fmna_nvs_read(long offset, uint8_t *buf, size_t size)
{
    uint32_t addr = fmna_nvs_fstorage.start_addr + offset;
    return nrf_fstorage_read(&fmna_nvs_fstorage, addr, buf, size);
}

static int fmna_nvs_write(long offset, const uint8_t *buf, size_t size)
{
    uint32_t err_code = NRF_SUCCESS;
    uint32_t addr     = fmna_nvs_fstorage.start_addr + offset;

    if ((err_code = nrf_fstorage_write(&fmna_nvs_fstorage, addr, buf, size, NULL)) == NRF_SUCCESS) {
        while (nrf_fstorage_is_busy(&fmna_nvs_fstorage)) {
        }
    }

    return err_code;
}

static int fmna_nvs_erase(long offset, size_t size)
{
    uint32_t err_code = NRF_SUCCESS;
    uint32_t addr     = fmna_nvs_fstorage.start_addr + offset;

    if ((err_code = nrf_fstorage_erase(&fmna_nvs_fstorage, addr, size, NULL)) == NRF_SUCCESS) {
        while (nrf_fstorage_is_busy(&fmna_nvs_fstorage)) {
        }
    }

    return err_code;
}

/* define flash device */
const struct nvs_flash_dev fmna_nvs_flash = {
    .erase_value  = 0xff,
    .page_size    = FMNA_NVS_PAGE_SIZE,
    .sector_size  = FMNA_NVS_PAGE_SIZE,
    .sector_count = (FSTORAGE_FMNA_NVS_END_ADDR - FSTORAGE_FMNA_NVS_START_ADDR + 1) / FMNA_NVS_PAGE_SIZE,
    .start_addr   = FSTORAGE_FMNA_NVS_START_ADDR,
    .end_addr     = FSTORAGE_FMNA_NVS_END_ADDR,
    .write_gran   = 4,

    .mutex = {0},
    .ops   = {fmna_nvs_init, fmna_nvs_read, fmna_nvs_write, fmna_nvs_erase}
};


/*-------------------------------------- platform interface -------------------------------------------*/
static struct nvs_fs fmna_nvs_obj = {
    .flash_dev = &fmna_nvs_flash,
};

void fmna_storage_init(void)
{
    static uint8_t init = 0;

    if (!init) {
        nvs_mount(&fmna_nvs_obj);
        init = 1;
    }
}

int fmna_storage_read(uint16_t id, void *data, size_t size)
{
    return nvs_read(&fmna_nvs_obj, id, data, size);
}

int fmna_storage_write(uint16_t id, const void *data, size_t size)
{
    return nvs_write(&fmna_nvs_obj, id, data, size);
}

int fmna_storage_erase(uint16_t id)
{
    return nvs_delete(&fmna_nvs_obj, id);
}
