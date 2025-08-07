/*
*      Copyright (C) 2020 Apple Inc. All Rights Reserved.
*
*      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
*      which is contained in the License.txt file distributed with the Find My Network ADK,
*      and only to those who accept that license.
*/

#ifndef fmna_malloc_platform_h
#define fmna_malloc_platform_h

#include <stdint.h>

#define FMNA_HEAP_SIZE 8192

extern void fmna_malloc_platform_init(void);
extern void fmna_free(void *ptr);
extern void * fmna_malloc(size_t size);
extern void * fmna_realloc(void *ptr, size_t size);
extern void fmna_malloc_dump(void);

#endif /* fmna_malloc_platform_h */
