/*
*      Copyright (C) 2020 Apple Inc. All Rights Reserved.
*
*      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
*      which is contained in the License.txt file distributed with the Find My Network ADK,
*      and only to those who accept that license.
*/

#include "fmna_platform_includes.h"
#include "fmna_constants.h"
#include "fmna_util.h"
#include "fmna_version.h"

// FW version bit offsets as described in spec.
#define FW_VERSION_MAJOR_NUMBER_OFFSET  16
#define FW_VERSION_MINOR_NUMBER_OFFSET  8

static uint32_t m_fw_version = 0;

void fmna_version_init(void) {
    // Build the FW version value.
    
    m_fw_version |= FW_VERSION_REVISION_NUMBER;
    m_fw_version |= BF_VAL(FW_VERSION_MAJOR_NUMBER, 16, FW_VERSION_MAJOR_NUMBER_OFFSET);
    m_fw_version |= BF_VAL(FW_VERSION_MINOR_NUMBER, 8,  FW_VERSION_MINOR_NUMBER_OFFSET);
    
    FMNA_LOG_INFO("FW Version: 0x%08x", m_fw_version);
}

uint32_t fmna_version_get_fw_version(void) {
    FMNA_LOG_INFO("v%d.%d.%d", FW_VERSION_MAJOR_NUMBER, FW_VERSION_MINOR_NUMBER, FW_VERSION_REVISION_NUMBER);
    return m_fw_version;
}

