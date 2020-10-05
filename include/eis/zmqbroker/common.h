// Copyright (c) 2020 Intel Corporation.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM,OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

/**
 * @file
 * @brief Common utility functions used in the EIS ZeroMQ Broker
 */

#ifndef EIS_ZMQ_BROKER_INCLUDE_EIS_ZMQBROKER_COMMON_H_
#define EIS_ZMQ_BROKER_INCLUDE_EIS_ZMQBROKER_COMMON_H_

#include <eis/utils/logger.h>

// Helper macro for logging errors in ZeroMQ
#define LOG_ZMQ_ERROR(msg) \
    LOG_ERROR(msg ": [%d] %s", zmq_errno(), zmq_strerror(zmq_errno()));

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Helper method to verify that the given ZeroMQ curve key is of length 40.
 *
 * @param key - Key to verify
 * @return true if key is valid, otherwise return false
 */
bool verify_key_len(const char* key);

/**
 * ZeroMQ helper function to close a socket with no linger for currently
 * sending messages.
 *
 * @param socket - ZeroMQ socket pointer
 */
void close_zero_linger(void* socket);

/**
 * Helper function to get a string for the name of a ZeroMQ event.
 *
 * @param event - ZeroMQ event ID
 */
const char* get_event_str(int event);

/**
 * Helper method to see if any events occured on a given socket.
 *
 * @param monitor - ZeroMQ monitor socket
 * @param block   - Flag for whether or not to block until an event occurs
 * @return ZeroMQ event ID
 */
int get_monitor_event(void* monitor, bool block);

/**
 * Return string name for the given Linux scheduler policy.
 *
 * @param sched_policy - Scheduler policy
 * @return const char*
 */
const char* sched_policy_desc(int sched_policy);

/**
 * Parse the given log level string.
 *
 * \note The string must be one of the following: DEBUG, INFO, WARN, ERROR
 *
 * @param[in]  log_lvl_str - Log level string to parse
 * @param[out] log_lvl     - Output log level
 * @return True if successfully parse, False if not. Errors will be logged
 *  in the method accordingly.
 */
bool parse_log_level(const char* log_lvl_str, log_lvl_t* log_lvl);

/**
 * Parse the given Linux scheduler policy into it's corresponding integer
 * value.
 *
 * \note The string must be one of the following: SCHED_OTHER, SCHED_IDLE,
 *      SCHED_BATCH, SCHED_FIFO, SCHED_RR. See this Linux man page for more
 *      information:
 *      https://man7.org/linux/man-pages/man7/sched.7.html for more details
 *
 * @param[in]  sched_policy_str - Schedule policy name
 * @param[out] sched_policy     - Outputted integer value
 * @return True if successfully parsed, otherwise False. Errors will be logged
 *  in the method accordingly.
 */
bool parse_sched_policy(const char* sched_policy_str, int* sched_policy);

#ifdef __cplusplus
}  // __cplusplus
#endif

#endif  // EIS_ZMQ_BROKER_INCLUDE_EIS_ZMQBROKER_COMMON_H_
