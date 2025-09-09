#include <stdint.h>
#include <string.h>
#include "nrf_fstorage.h"
#include "nrf_fstorage_sd.h"
#include "nrf_fstorage_nvmc.h"
#include "nvs_def.h"
#include "nvs.h"
#include "ok_platform.h"

#define FSTORAGE_NVS_START_ADDR 0x66000
#define FSTORAGE_NVS_END_ADDR   0x68FFF
#define NVS_NRF5_PAGE_SIZE      0x1000

const struct nvs_flash_dev nvs_nrf52_flash;

static void nvs_data_evt_handler(nrf_fstorage_evt_t *p_evt)
{
    if (p_evt->result != NRF_SUCCESS) {
        OK_LOG_INFO("--> Event received: ERROR while executing an fstorage operation.");
        return;
    }

    switch (p_evt->id) {
        case NRF_FSTORAGE_EVT_WRITE_RESULT:
            OK_LOG_INFO("--> Write event: %d bytes at address 0x%x.", p_evt->len, p_evt->addr);
            break;
        case NRF_FSTORAGE_EVT_ERASE_RESULT:
            OK_LOG_INFO("--> Erase event: %d page from address 0x%x.", p_evt->len, p_evt->addr);
            break;
        default:
            OK_LOG_INFO("--> Event received: other event");
            break;
    }
}

NRF_FSTORAGE_DEF(nrf_fstorage_t nvs_data_fstorage) = {
    .evt_handler = nvs_data_evt_handler,
    .start_addr  = FSTORAGE_NVS_START_ADDR,
    .end_addr    = FSTORAGE_NVS_END_ADDR,
};

static int nvs_nrf52_init(void)
{
    nrf_fstorage_init(&nvs_data_fstorage, &nrf_fstorage_sd, NULL);
    return 0;
}

static int nvs_nrf52_read(long offset, uint8_t *buf, size_t size)
{
    uint32_t addr = nvs_data_fstorage.start_addr + offset;
    return nrf_fstorage_read(&nvs_data_fstorage, addr, buf, size);
}

static int nvs_nrf52_write(long offset, const uint8_t *buf, size_t size)
{
    uint32_t err_code = NRF_SUCCESS;
    uint32_t addr = nvs_data_fstorage.start_addr + offset;

    if ((err_code = nrf_fstorage_write(&nvs_data_fstorage, addr, buf, size, NULL)) == NRF_SUCCESS) {
        while (nrf_fstorage_is_busy(&nvs_data_fstorage)) {
        }
    }
    
    return err_code;
}

static int nvs_nrf52_erase(long offset, size_t size)
{
    uint32_t err_code = NRF_SUCCESS;
    uint32_t addr = nvs_data_fstorage.start_addr + offset;

    if ((err_code = nrf_fstorage_erase(&nvs_data_fstorage, addr, size / NVS_NRF5_PAGE_SIZE, NULL)) == NRF_SUCCESS) {    
        while (nrf_fstorage_is_busy(&nvs_data_fstorage)) {
        }
    }

    return err_code;
}

/* define flash device */
const struct nvs_flash_dev nvs_nrf52_flash = {
    .erase_value = 0xff,
    .page_size = NVS_NRF5_PAGE_SIZE,
    .sector_size = NVS_NRF5_PAGE_SIZE,
    .sector_count = (FSTORAGE_NVS_END_ADDR - FSTORAGE_NVS_START_ADDR + 1) / NVS_NRF5_PAGE_SIZE,
    .start_addr = FSTORAGE_NVS_START_ADDR,
    .end_addr = FSTORAGE_NVS_END_ADDR,
    .write_gran = 4,

    .mutex = {0},
    .ops = {nvs_nrf52_init, nvs_nrf52_read, nvs_nrf52_write, nvs_nrf52_erase}
};


/*--------------------------------------test code-------------------------------------------*/
#define NVS_BLOB_ID    1
#define NVS_STRING_ID  2
#define NVS_FILE_ID    3
#define NVS_TEST_CYCLES 100

/* blob */
__attribute__((unused)) static uint8_t blob_data[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

/* string */
__attribute__((unused)) static char string[] = "12345";

__attribute__((unused)) static const char test_ca_crt[]=
"-----BEGIN CERTIFICATE-----\r\n" \
"MIICCTCCAa4CCQD98hA2cug6fDAKBggqhkjOPQQDAjCBizELMAkGA1UEBhMCQ04x\r\n" \
"CzAJBgNVBAgMAkdEMQswCQYDVQQHDAJTWjESMBAGA1UECgwJM2lyb2JvdGl4MQww\r\n" \
"VQQHDAJTWjESMBAGA1UECgwJM2lyb2JvdGl4MQwwCgYDVQQLDANJT1QxGDAWBgNV\r\n" \
"1n6bZGbjN4j9ZgIhAKILhfvcMtcN/fiB8AfBdWWr+OVAEZq7te9foPBiz3il\r\n" \
"-----END CERTIFICATE-----";

/* NVS object */
static struct nvs_fs nvs_obj = {
    .flash_dev = &nvs_nrf52_flash,
};

static char cert_buf[512];

static void xdebug_nvs_flash_init(void)
{
    static uint8_t init = 0; 

    if (!init) {
        nvs_mount(&nvs_obj);
        init = 1;
    } 
}

static void xdebug_nvs_blob_sample(struct nvs_fs *fs)
{
    uint8_t blob_tmp[10] = {0};
    
    { /* write blob */
        nvs_write(fs, NVS_BLOB_ID, blob_data, sizeof(blob_data));
        OK_LOG_INFO("set nvs blob: %d~%d\n", blob_data[0], blob_data[9]);
    }
    
    { /* read blob */
        nvs_read(fs, NVS_BLOB_ID, blob_tmp, sizeof(blob_tmp));
        OK_LOG_INFO("get nvs blob: %d~%d\n", blob_tmp[0], blob_tmp[9]);
    }
    
    { /* change blob */
        uint8_t tmp = blob_data[0];
        blob_data[0] = blob_data[9];
        blob_data[9] = tmp;
    }
}

static void xdebug_nvs_string_sample(struct nvs_fs *fs)
{
    uint8_t m_string[10] = {0};
    
    { /* write blob */
        nvs_write(fs, NVS_STRING_ID, string, strlen(string));
        OK_LOG_INFO("set nvs string: %s\n", string);
    }
    
    { /* read blob */
        nvs_read(fs, NVS_STRING_ID, m_string, sizeof(m_string));
        OK_LOG_INFO("get nvs string: %s\n", m_string);
    }
    
    { /* change blob */
        uint8_t tmp = string[0];
        string[0] = string[strlen(string)-1];
        string[strlen(string)-1] = tmp;
    }
}

static void xdebug_nvs_file_sample(struct nvs_fs *fs)
{
    char file[32] = {0};

    { /* write file */
        nvs_write(fs, NVS_FILE_ID, test_ca_crt, strlen(test_ca_crt));
        memcpy(file, test_ca_crt, strlen("-----BEGIN CERTIFICATE-----"));
        OK_LOG_INFO("set cert file head: %s\n", file);
        
        memset(file, 0x00, sizeof(file));
        
        memcpy(file, test_ca_crt + strlen(test_ca_crt) - strlen("-----END CERTIFICATE-----"), strlen("-----END CERTIFICATE-----"));
        OK_LOG_INFO("set cert file tail: %s\n", file);
    }
    
    { /* read file */
        nvs_read(fs, NVS_FILE_ID, cert_buf, sizeof(cert_buf));
        memcpy(file, cert_buf, strlen("-----BEGIN CERTIFICATE-----"));
        OK_LOG_INFO("get cert file head: %s\n", file);
        
        memset(file, 0x00, sizeof(file));
        
        memcpy(file, cert_buf + strlen(cert_buf) - strlen("-----END CERTIFICATE-----"), strlen("-----END CERTIFICATE-----"));
        OK_LOG_INFO("get cert file tail: %s\n", file);
    }
}

void xdebug_nvs_test(void)
{
    xdebug_nvs_flash_init();

    for (int i = 0; i < NVS_TEST_CYCLES; i++) {
        OK_LOG_INFO("\n---------------- start ---------------");
    
        /* blob sample */
        xdebug_nvs_blob_sample(&nvs_obj);
        
        /* blob sample */
        xdebug_nvs_string_sample(&nvs_obj);
        
        /* blob sample */
        xdebug_nvs_file_sample(&nvs_obj);
        
        OK_LOG_INFO("\n---------------- end ---------------");   
    }
}
