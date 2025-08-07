#ifndef __OK_PLATFORM_CONFIG_H__
#define __OK_PLATFORM_CONFIG_H__

#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
#include "ecdsa.h"
#include "ok_storage.h"
#include "ok_device_config.h"

#define OK_LOG_INFO(...)    NRF_LOG_INFO(__VA_ARGS__); \
                            NRF_LOG_FLUSH();
#define OK_LOG_WARN(...)    NRF_LOG_WARNING(__VA_ARGS__); \
                            NRF_LOG_FLUSH();
#define OK_LOG_ERROR(...)   NRF_LOG_ERROR(__VA_ARGS__); \
                            NRF_LOG_FLUSH();
#define OK_LOG_INFO_NOFLUSH(...)    NRF_LOG_INFO(__VA_ARGS__)
#define OK_LOG_WARN_NOFLUSH(...)    NRF_LOG_WARNING(__VA_ARGS__)
#define OK_LOG_ERROR_NOFLUSH(...)   NRF_LOG_ERROR(__VA_ARGS__)

#endif /* __OK_PLATFORM_CONFIG_H__ */
