/*
*      Copyright (C) 2020 Apple Inc. All Rights Reserved.
*
*      Find My Network ADK is licensed under Apple Inc.’s MFi Sample Code License Agreement,
*      which is contained in the License.txt file distributed with the Find My Network ADK,
*      and only to those who accept that license.
*/

#include "fmna_platform_includes.h"
#include "fmna_util.h"
#include "fmna_motion_detection.h"
#include "fmna_state_machine.h"
#include "fmna_constants.h"

#include "fmna_motion_detection_platform.h"

#define SEPARATED_UT_MOTION_SAMPLING_RATE1_MS             SEC_TO_MSEC(10)    // Passive poll rate
#define SEPARATED_UT_MOTION_SAMPLING_RATE2_MS             500                // Active poll rate
#define SEPARATED_UT_MOTION_ACTIVE_POLL_DURATION_MS       SEC_TO_MSEC(20)
#define SEPARATED_UT_MOTION_BACKOFF_MS                    HOURS_TO_MSEC(6)
#define SEPARATED_UT_MOTION_MAX_SOUND_COUNT               10

static bool     m_motion_active_polling_enabled = false;
static bool     m_motion_active_polling_ended   = false;
static uint16_t m_motion_check_poll_rate_ms     = SEPARATED_UT_MOTION_SAMPLING_RATE1_MS;
static uint8_t  m_motion_sound_count            = 0;

APP_TIMER_DEF(m_motion_poll_timer_id);
static void motion_poll_timer_timeout_handler(void *p_context);

APP_TIMER_DEF(m_motion_active_poll_duration_timer_id);
static void motion_active_poll_duration_timer_timeout_handler(void *p_context);

static uint32_t m_motion_backoff_timeout_ms = SEPARATED_UT_MOTION_BACKOFF_MS;
APP_TIMER_DEF(m_motion_backoff_timer_id);
static void motion_backoff_timeout_handler(void *p_context);

void fmna_motion_detection_init(void) {
    fmna_ret_code_t ret_code = FMNA_SUCCESS;
    
    ret_code = app_timer_create(&m_motion_poll_timer_id, APP_TIMER_MODE_REPEATED, motion_poll_timer_timeout_handler);
    FMNA_ERROR_CHECK(ret_code);
    ret_code = app_timer_create(&m_motion_active_poll_duration_timer_id, APP_TIMER_MODE_SINGLE_SHOT, motion_active_poll_duration_timer_timeout_handler);
    FMNA_ERROR_CHECK(ret_code);
    ret_code = app_timer_create(&m_motion_backoff_timer_id, APP_TIMER_MODE_SINGLE_SHOT, motion_backoff_timeout_handler);
    FMNA_ERROR_CHECK(ret_code);
    
    //TODO: Any platform-specific motion detection initializations.
}

static void stop_all_timers(void) {
    fmna_ret_code_t ret_code = app_timer_stop(m_motion_poll_timer_id);
    if (FMNA_SUCCESS != ret_code) {
        FMNA_LOG_ERROR("error %d stopping m_motion_poll_timer_id", ret_code);
    }
    
    // Stop the active poll duration timer, if applicable
    ret_code = app_timer_stop(m_motion_active_poll_duration_timer_id);
    if (FMNA_SUCCESS != ret_code) {
        FMNA_LOG_ERROR("error %d stopping m_motion_active_poll_duration_timer_id", ret_code);
    }
    
    // Stop the accel backoff timer, if applicable
    ret_code = app_timer_stop(m_motion_backoff_timer_id);
    if (FMNA_SUCCESS != ret_code) {
        FMNA_LOG_ERROR("error %d stopping m_motion_backoff_timer_id", ret_code);
    }
}

static void motion_active_poll_duration_timeout_sched_handler(void *p_event_data, uint16_t event_size) {
    // Haven't detected movement for active polling duration. Turn off motion detection
    // and start the backoff timer so that we only reinitialize after X hours.
    
    FMNA_LOG_INFO("motion_active_poll_duration_timeout_sched_handler");
    
    fmna_ret_code_t ret_code = app_timer_stop(m_motion_poll_timer_id);
    if (FMNA_SUCCESS != ret_code) {
        FMNA_LOG_ERROR("e,%x", "error %d stopping m_motion_poll_timer_id", ret_code);
    }
    m_motion_active_polling_enabled = false;
    m_motion_active_polling_ended   = true;
    
    ret_code = app_timer_start(m_motion_backoff_timer_id, APP_TIMER_TICKS(m_motion_backoff_timeout_ms), NULL);
    if (FMNA_SUCCESS != ret_code) {
        FMNA_LOG_ERROR("f,%x", "error %d starting m_motion_backoff_timer_id", ret_code);
    }
}

void fmna_motion_detection_start_active_polling(void) {
    ret_code_t ret_code;
    
    // initialize to active poll rate
    m_motion_check_poll_rate_ms = SEPARATED_UT_MOTION_SAMPLING_RATE2_MS;
    
    // Check if active poll duration completed during motion detection play sound.
    if (!m_motion_active_polling_ended) {
        if (m_motion_sound_count >= SEPARATED_UT_MOTION_MAX_SOUND_COUNT) {
            // Max motion detect sounds played, we should preemptively not restart poll timer and go into backoff mode..
            FMNA_LOG_INFO("Max motion detection sounds played. Stopping polling, going to backoff.");
            
            // Stop the polling timer.
            app_timer_stop(m_motion_active_poll_duration_timer_id);
            
            // Schedule the handler to cleanup and go into motion detection backoff.
            app_sched_event_put(NULL, NULL, motion_active_poll_duration_timeout_sched_handler);
        }
        else {
            // We are still active polling... (re)start polling.
            app_timer_start(m_motion_poll_timer_id, APP_TIMER_TICKS(m_motion_check_poll_rate_ms), NULL);
            
            if (!m_motion_active_polling_enabled) {
                // Start active polling for the first time.
                FMNA_LOG_INFO("Starting active poll duration timer");
                // If we are currently active polling, don't restart the timer.
                ret_code = app_timer_start(m_motion_active_poll_duration_timer_id, APP_TIMER_TICKS(SEPARATED_UT_MOTION_ACTIVE_POLL_DURATION_MS), NULL);
                if (FMNA_SUCCESS != ret_code) {
                    FMNA_LOG_ERROR("m_motion_active_poll_duration_timer_id start err %d", ret_code);
                }
                m_motion_active_polling_enabled = true;
            }
        }
    }
}

void motion_poll_timer_timeout_handler(void *p_context) {
    FMNA_LOG_INFO("motion_poll_timer_timeout_handler");
    
    // Check if we detect motion, e.g. orientation change.
    if (fmna_motion_detection_platform_is_motion_detected()) {
        fmna_state_machine_dispatch_event(FMNA_SM_EVENT_MOTION_DETECTED);
        m_motion_sound_count++;
    }
}

void motion_backoff_timeout_handler(void *p_context) {
    FMNA_LOG_INFO("motion_backoff_timeout_handler");
    
    // Backoff period is over, and we are still in Separated. Re-init motion detection.
    fmna_motion_detection_start();
}

void motion_active_poll_duration_timer_timeout_handler(void *p_context) {
    FMNA_LOG_INFO("motion_active_poll_duration_timer_timeout_handler");
    
    // Schedule poll timer stop and blackout timer start.
    app_sched_event_put(NULL, NULL, motion_active_poll_duration_timeout_sched_handler);
}

void fmna_motion_detection_stop(void) {
    FMNA_LOG_INFO("fmna_motion_detection_stop");
    
    stop_all_timers();
    
    // Power off motion detection, cleanup.
    fmna_motion_detection_platform_deinit();
}

void fmna_motion_detection_start(void) {
    FMNA_LOG_INFO("fmna_motion_detection_start");
    
    // Initialize the poll rate
    m_motion_check_poll_rate_ms = SEPARATED_UT_MOTION_SAMPLING_RATE1_MS;
    
    // Reset state
    m_motion_active_polling_ended   = false;
    m_motion_active_polling_enabled = false;
    m_motion_sound_count   = 0;
    
    //TODO: Any platform-specific motion detection initializations.
    fmna_motion_detection_platform_init();
    
    // Start passive polling to detect motion
    fmna_ret_code_t ret_code = app_timer_start(m_motion_poll_timer_id, APP_TIMER_TICKS(m_motion_check_poll_rate_ms), NULL);
    if (FMNA_SUCCESS != ret_code) {
        FMNA_LOG_ERROR("error 0x%x starting m_motion_poll_timer_id", ret_code);
    }
}

#ifdef DEBUG
void fmna_motion_detection_set_separated_ut_backoff_timeout_seconds(uint32_t separated_ut_backoff_timeout_seconds) {
    m_motion_backoff_timeout_ms = SEC_TO_MSEC(separated_ut_backoff_timeout_seconds);
}
#endif //DEBUG
