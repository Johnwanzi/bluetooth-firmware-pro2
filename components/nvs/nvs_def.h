#ifndef __NVS_DEF_H__
#define __NVS_DEF_H__

#include <stdint.h>
#include <stdio.h>
#include "ok_platform.h"

#define NVS_LOG_DEBUG(...)    OK_LOG_INFO(__VA_ARGS__)
#define NVS_LOG_INFO(...)     OK_LOG_INFO(__VA_ARGS__)
#define NVS_LOG_WARN(...)     OK_LOG_WARN(__VA_ARGS__)

#pragma pack(push)
#pragma pack(1)
struct nvs_flash_dev {
    uint8_t erase_value;    /* oxff */
    
    uint16_t page_size;     /* flash erase unit*/
    uint16_t sector_size;    /* multiple page_size*/
	uint16_t sector_count;   /* (end_addr - start_addr + 1)/sector_size */
    
    size_t start_addr;    /* nvs start address */
    size_t end_addr;      /* nvs end address */
    
    /* single write granularity, unit: byte*/
    size_t write_gran;
    
    struct {
        void (*lock_init)(void);
        void (*lock)(void);
        void (*unlock)(void);
    } mutex;
    
    struct {
        int (*init)(void);
        int (*read)(long offset, uint8_t *buf, size_t size);
        int (*write)(long offset, const uint8_t *buf, size_t size);
        int (*erase)(long offset, size_t size);
    } ops;
};
#pragma pack(pop)

#endif /* __NVS_DEF_H__ */
