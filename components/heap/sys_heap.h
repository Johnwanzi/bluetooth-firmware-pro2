#ifndef __SYS_HEAP_H__
#define __SYS_HEAP_H__

/********************************** common definition ****************************************/
#define RT_ALIGN_SIZE 4
#define RT_ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define RT_ALIGN_DOWN(x, a) ((x) & ~((a) - 1))
#define RT_NULL 0

#define rt_memcpy  memcpy
#define rt_memset  memset

/* #define RT_MEM_DEBUG */
#define RT_MEM_STATS


/********************************** platform definition *******************************/
#include "nrf_assert.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"


#define RT_ASSERT(...)     ASSERT(__VA_ARGS__)

#define RT_DEBUG_LOG(...)  NRF_LOG_DEBUG(__VA_ARGS__)
#define RT_WARN_LOG(...)   NRF_LOG_WARNING(__VA_ARGS__)

void rt_system_heap_init(void *begin_addr, void *end_addr);
void *rt_malloc(size_t size);
void *rt_realloc(void *rmem, size_t newsize);
void *rt_calloc(size_t count, size_t size);
void rt_free(void *rmem);

#ifdef RT_MEM_STATS
void rt_memory_info(uint32_t *total, uint32_t *used, uint32_t *max_used);
#endif

#define sys_heap_init rt_system_heap_init
#define sys_malloc rt_malloc
#define sys_realloc rt_realloc
#define sys_calloc rt_calloc
#define sys_free rt_free
#define sys_mem_info rt_memory_info

#endif /* __SYS_HEAP_H__ */
