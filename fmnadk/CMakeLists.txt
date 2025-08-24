cmake_minimum_required(VERSION 3.22.1)

###############################
# Toolchain
include("../toolchain.cmake")

###############################
# Project
project(FMNADK_LIB LANGUAGES C CXX ASM)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

message(STATUS "${CMAKE_PROJECT_NAME} Build Type: ${CMAKE_BUILD_TYPE}")

###############################
# fmna core source files
set(
  FMNA_CORE_SRC
  ${PROJECT_SOURCE_DIR}/adk/fmna/fmna_adv.c
  ${PROJECT_SOURCE_DIR}/adk/fmna/fmna_config_control_point.c
  ${PROJECT_SOURCE_DIR}/adk/fmna/fmna_connection.c
  ${PROJECT_SOURCE_DIR}/adk/fmna/fmna_crypto.c
  ${PROJECT_SOURCE_DIR}/adk/fmna/fmna_debug_control_point.c
  ${PROJECT_SOURCE_DIR}/adk/fmna/fmna_gatt.c
  ${PROJECT_SOURCE_DIR}/adk/fmna/fmna_motion_detection.c
  ${PROJECT_SOURCE_DIR}/adk/fmna/fmna_nfc.c
  ${PROJECT_SOURCE_DIR}/adk/fmna/fmna_nonowner_control_point.c
  ${PROJECT_SOURCE_DIR}/adk/fmna/fmna_paired_owner_control_point.c
  ${PROJECT_SOURCE_DIR}/adk/fmna/fmna_pairing_control_point.c
  ${PROJECT_SOURCE_DIR}/adk/fmna/fmna_state_machine.c
  ${PROJECT_SOURCE_DIR}/adk/fmna/fmna_version.c
)

# Platform source files
set(
  FMNA_PLATFORM_SRC
  ${PROJECT_SOURCE_DIR}/adk/platform/fmna_adv_platform.c
  ${PROJECT_SOURCE_DIR}/adk/platform/fmna_battery_platform.c
  ${PROJECT_SOURCE_DIR}/adk/platform/fmna_ble_stack_platform.c
  ${PROJECT_SOURCE_DIR}/adk/platform/fmna_connection_platform.c
  ${PROJECT_SOURCE_DIR}/adk/platform/fmna_fault_platform.c
  ${PROJECT_SOURCE_DIR}/adk/platform/fmna_gatt_platform.c
  ${PROJECT_SOURCE_DIR}/adk/platform/fmna_malloc_platform.c
  ${PROJECT_SOURCE_DIR}/adk/platform/fmna_motion_detection_platform.c
  ${PROJECT_SOURCE_DIR}/adk/platform/fmna_nfc_platform.c
  ${PROJECT_SOURCE_DIR}/adk/platform/fmna_peer_manager.c
  ${PROJECT_SOURCE_DIR}/adk/platform/fmna_sound_platform.c
)

# Crypto source files (conditional)
# WolfSSL crypto source files
set(
  WOLFSSL_SRC
  ${PROJECT_SOURCE_DIR}/adk/crypto/fmna-crypto-wrapper-reference/fm-crypto.c

  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/aes.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/asn.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/coding.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/ecc.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/error.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/hash.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/hmac.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/integer.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/logging.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/pwdbased.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/random.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/sha256.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/sp_int.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/sp_c32.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/sp_cortexm.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/tfm.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/wc_port.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/wolfmath.c
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl/wolfcrypt/src/port/nrf51.c
)

# App source files
set(
  FMNA_APP_SRC
  ${PROJECT_SOURCE_DIR}/fmna_app.c
  ${PROJECT_SOURCE_DIR}/fmna_storage.c
)

# Include directories
set(
  FMNA_INC
  ${PROJECT_SOURCE_DIR}/adk/fmna
  ${PROJECT_SOURCE_DIR}/adk/platform
  ${PROJECT_SOURCE_DIR}/adk/crypto
  ${PROJECT_SOURCE_DIR}/adk/crypto/wolfssl
  ${PROJECT_SOURCE_DIR}/adk/crypto/fmna-crypto-wrapper-reference
)

###############################
# NRF SDK
set(NRF_SDK_ROOT "${PROJECT_SOURCE_DIR}/../ble-firmware")

set(
  NRF_SDK_INC

  ${NRF_SDK_ROOT}/components
  ${NRF_SDK_ROOT}/components/boards
  ${NRF_SDK_ROOT}/components/libraries/bsp
  ${NRF_SDK_ROOT}/components/libraries/button
  ${NRF_SDK_ROOT}/components/libraries/log
  ${NRF_SDK_ROOT}/components/libraries/log/src
  ${NRF_SDK_ROOT}/components/libraries/fstorage
  ${NRF_SDK_ROOT}/components/libraries/mutex
  ${NRF_SDK_ROOT}/components/libraries/gpiote
  ${NRF_SDK_ROOT}/components/libraries/queue
  ${NRF_SDK_ROOT}/components/libraries/pwr_mgmt
  ${NRF_SDK_ROOT}/components/libraries/mpu
  ${NRF_SDK_ROOT}/components/libraries/experimental_section_vars
  ${NRF_SDK_ROOT}/components/libraries/slip
  ${NRF_SDK_ROOT}/components/libraries/delay
  ${NRF_SDK_ROOT}/components/libraries/mem_manager
  ${NRF_SDK_ROOT}/components/libraries/csense_drv
  ${NRF_SDK_ROOT}/components/libraries/memobj
  ${NRF_SDK_ROOT}/components/libraries/low_power_pwm
  ${NRF_SDK_ROOT}/components/libraries/svc
  ${NRF_SDK_ROOT}/components/libraries/uart
  ${NRF_SDK_ROOT}/components/libraries/atomic
  ${NRF_SDK_ROOT}/components/libraries/scheduler
  ${NRF_SDK_ROOT}/components/libraries/cli
  ${NRF_SDK_ROOT}/components/libraries/crc16
  ${NRF_SDK_ROOT}/components/libraries/util
  ${NRF_SDK_ROOT}/components/libraries/csense
  ${NRF_SDK_ROOT}/components/libraries/balloc
  ${NRF_SDK_ROOT}/components/libraries/ecc
  ${NRF_SDK_ROOT}/components/libraries/hardfault
  ${NRF_SDK_ROOT}/components/libraries/hci
  ${NRF_SDK_ROOT}/components/libraries/timer
  ${NRF_SDK_ROOT}/components/libraries/sortlist
  ${NRF_SDK_ROOT}/components/libraries/twi_mngr
  ${NRF_SDK_ROOT}/components/libraries/strerror
  ${NRF_SDK_ROOT}/components/libraries/crc32
  ${NRF_SDK_ROOT}/components/libraries/ringbuf
  ${NRF_SDK_ROOT}/components/libraries/gfx
  ${NRF_SDK_ROOT}/components/libraries/twi_sensor
  ${NRF_SDK_ROOT}/components/libraries/atomic_fifo
  ${NRF_SDK_ROOT}/components/libraries/crypto
  ${NRF_SDK_ROOT}/components/libraries/fds
  ${NRF_SDK_ROOT}/components/libraries/atomic_flags
  ${NRF_SDK_ROOT}/components/libraries/stack_guard
  ${NRF_SDK_ROOT}/components/ble/ble_advertising
  ${NRF_SDK_ROOT}/components/ble/common
  ${NRF_SDK_ROOT}/components/ble/ble_dtm
  ${NRF_SDK_ROOT}/components/ble/ble_services/ble_tps
  ${NRF_SDK_ROOT}/components/ble/ble_racp
  ${NRF_SDK_ROOT}/components/ble/peer_manager
  ${NRF_SDK_ROOT}/components/ble/nrf_ble_gatt
  ${NRF_SDK_ROOT}/components/softdevice/common
  ${NRF_SDK_ROOT}/components/softdevice/s132/headers
  ${NRF_SDK_ROOT}/components/softdevice/s132/headers/nrf52
  ${NRF_SDK_ROOT}/external/utf_converter
  ${NRF_SDK_ROOT}/external/fprintf
  ${NRF_SDK_ROOT}/external/segger_rtt
  ${NRF_SDK_ROOT}/components/toolchain/cmsis/include
  ${NRF_SDK_ROOT}/modules/nrfx
  ${NRF_SDK_ROOT}/modules/nrfx/drivers/include
  ${NRF_SDK_ROOT}/modules/nrfx/hal
  ${NRF_SDK_ROOT}/modules/nrfx/mdk
  ${NRF_SDK_ROOT}/integration/nrfx
  ${NRF_SDK_ROOT}/integration/nrfx/legacy
)

########################### Create FMNADK Static Library ###################
# NRF SDK
set(SDK_BUILD_ROOT "${PROJECT_SOURCE_DIR}/../")

# Create Fmnadk Static Library

add_library(
  fmnadk STATIC
  ${FMNA_CORE_SRC}
  ${FMNA_PLATFORM_SRC}
  ${WOLFSSL_SRC}
  ${FMNA_APP_SRC}
)

# Include directories
target_include_directories(
  fmnadk PUBLIC
  ${PROJECT_SOURCE_DIR}
)

# Private include directories - not exposed to users of the library
target_include_directories(
  fmnadk PRIVATE
  ${FMNA_INC}
  ${NRF_SDK_INC}
  ${SDK_BUILD_ROOT}/app
  ${SDK_BUILD_ROOT}/app/ble
  ${SDK_BUILD_ROOT}/components/heap
  ${SDK_BUILD_ROOT}/components/nvs
)

########################### Compile definitions #############################
target_compile_definitions(
  fmnadk PUBLIC
  # ARM architecture definitions
  __SIZEOF_WCHAR_T=4
  __ARM_ARCH_7EM__
  __ARM_ARCH_FPV4_SP_D16__
  INITIALIZE_USER_SECTIONS
  NO_VTOR_CONFIG

  # Project flags
  APP_TIMER_V2
  APP_TIMER_V2_RTC1_ENABLED
  CONFIG_GPIO_AS_PINRESET
  BOARD_PCA10040
  FLOAT_ABI_HARD
  NRF52
  NRF52832_XXAA
  NRF52_PAN_74
  NRF_SD_BLE_API_VERSION=7
  S132
  SOFTDEVICE_PRESENT
  SWI_DISABLE0

  WOLFSSL_USER_SETTINGS
)

########################### Compile and linker options #######################
set(MCPU_FLAGS 
  -mthumb
  -mcpu=cortex-m4
)

set(VFP_FLAGS  
  -mfloat-abi=hard
  -mfpu=fpv4-sp-d16
)

set(CMAKE_COMMON_FLAGS
  -g3
  -ffunction-sections
  -fdata-sections
  -fno-strict-aliasing
  -fdiagnostics-color=always
  -fno-builtin
  -fno-common
  -fshort-enums
  -Wall
  -Wdouble-promotion
  -Werror
  -Wno-unused-parameter
  -Wno-incompatible-pointer-types
  -Wno-int-conversion
  -Wno-stringop-overflow
  -Wno-maybe-uninitialized
)

target_compile_options(
  fmnadk PRIVATE
  ${MCPU_FLAGS}
  ${VFP_FLAGS}
  ${CMAKE_COMMON_FLAGS}
)

# Link options
target_link_options(
  fmnadk PRIVATE

  # Linker flags
  --specs=nano.specs
  --specs=nosys.specs

  # Linker symbols and options
  -Wl,--defsym=__vfprintf=__vfprintf_long
  -Wl,--defsym=__vfscanf=__vfscanf_int
  -Wl,-X
  -Wl,--omagic
  -Wl,-eReset_Handler
  -Wl,--fatal-warnings
  -Wl,-EL
  -Wl,--gc-sections
  -Wl,-u_vectors
  -Wl,--emit-relocs

  -Wl,-print-memory-usage
)

########################### Install #############################
# Set install prefix to current library directory
set(CMAKE_INSTALL_PREFIX "${PROJECT_SOURCE_DIR}" CACHE PATH "Installation Directory" FORCE)

# Install library
install(
  TARGETS fmnadk
  ARCHIVE DESTINATION lib
)

# Install only the public header file
install(
  FILES ${PROJECT_SOURCE_DIR}/fmna_app.h
  DESTINATION lib
) 