/*
*      Copyright (C) 2020 Apple Inc. All Rights Reserved.
*
*      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
*      which is contained in the License.txt file distributed with the Find My Network ADK,
*      and only to those who accept that license.
*/

#include <stdint.h>
#include <stdlib.h>
#include "sys_heap.h"
#include "fmna_malloc_platform.h"

#include "nrf_log.h"

static uint8_t fmna_heap[FMNA_HEAP_SIZE];

void fmna_malloc_platform_init(void) {
    sys_heap_init((void *)fmna_heap, (void *)(fmna_heap + FMNA_HEAP_SIZE));
}
void fmna_free(void *ptr) {
    rt_free(ptr);
}

void * fmna_malloc(size_t size) {
    return sys_malloc(size);
}

void * fmna_realloc(void *ptr, size_t size) {
    return sys_realloc(ptr, size);
}

void fmna_malloc_dump(void) {
#ifdef RT_MEM_STATS
    uint32_t total = 0, used = 0, max_used = 0;
    sys_mem_info(&total, &used, &max_used);

    NRF_LOG_INFO("Heap: total=%d, used=%d, max_used=%d", total, used, max_used);
#endif
}
