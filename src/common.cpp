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
 * @brief Common utility implementations
 */

#include "eis/zmqbroker/common.h"
#include <safe_lib.h>
#include <zmq.h>
#include <pthread.h>

// Implementation of C utilities

#include <stdlib.h>
#include <string.h>

bool verify_key_len(const char* key) {
    size_t key_len = strlen(key);
    if (key_len != 40) {
        LOG_ERROR("ZeroMQ curve key must be 40, not %d", (int) key_len);
        return false;
    }
    return true;
}

void close_zero_linger(void* socket) {
    int linger = 0;
    zmq_setsockopt(socket, ZMQ_LINGER, &linger, sizeof(linger));
    zmq_close(socket);
}

const char* get_event_str(int event) {
    switch (event) {
        case ZMQ_EVENT_CONNECTED:       return "ZMQ_EVENT_CONNECTED";
        case ZMQ_EVENT_CONNECT_DELAYED: return "ZMQ_EVENT_CONNECT_DELAYED";
        case ZMQ_EVENT_CONNECT_RETRIED: return "ZMQ_EVENT_CONNECT_RETRIED";
        case ZMQ_EVENT_LISTENING:       return "ZMQ_EVENT_LISTENING";
        case ZMQ_EVENT_BIND_FAILED:     return "ZMQ_EVENT_BIND_FAILED";
        case ZMQ_EVENT_ACCEPTED:        return "ZMQ_EVENT_ACCEPTED";
        case ZMQ_EVENT_CLOSED:          return "ZMQ_EVENT_CLOSED";
        case ZMQ_EVENT_CLOSE_FAILED:    return "ZMQ_EVENT_CLOSE_FAILED";
        case ZMQ_EVENT_DISCONNECTED:    return "ZMQ_EVENT_DISCONNECTED";
        case ZMQ_EVENT_MONITOR_STOPPED: return "ZMQ_EVENT_MONITOR_STOPPED";
        case ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL:
            return "ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL";
        case ZMQ_EVENT_HANDSHAKE_SUCCEEDED:
            return "ZMQ_EVENT_HANDSHAKE_SUCCEEDED";
        case ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL:
            return "ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL";
        case ZMQ_EVENT_HANDSHAKE_FAILED_AUTH:
            return "ZMQ_EVENT_HANDSHAKE_FAILED_AUTH";
        default: return "";
    }
}

int get_monitor_event(void* monitor, bool block) {
    zmq_msg_t msg;
    zmq_msg_init(&msg);

    int flag = ZMQ_DONTWAIT;
    if (block)
        flag = 0;

    if (zmq_msg_recv(&msg, monitor, flag) == -1) {
        zmq_msg_close(&msg);
        if (zmq_errno() == EAGAIN && !block) {
            return 0;
        }
        return -1;
    }

    // Get the event which occurred
    uint16_t event = *reinterpret_cast<uint16_t*>(
            reinterpret_cast<uint8_t*>(zmq_msg_data(&msg)));
    zmq_msg_close(&msg);

    LOG_DEBUG("ZeroMQ socket event: %s", get_event_str(event));

    // Retrieve second frame
    zmq_msg_init(&msg);
    // Ignore any errors since we do not care about the contents of the message
    zmq_msg_recv(&msg, monitor, 0);
    zmq_msg_close(&msg);

    return event;
}

const char* sched_policy_desc(int sched_policy) {
    switch (sched_policy) {
        case SCHED_OTHER: return "SCHED_OTHER";
        case SCHED_IDLE:  return "SCHED_IDLE";
        case SCHED_BATCH: return "SCHED_BATCH";
        case SCHED_FIFO:  return "SCHED_FIFO";
        case SCHED_RR:    return "SCHED_RR";
        default:          return "UNKNOWN";
    }
}

// Helper macro for checking if a string is equal to the given target and then
// setting output equal to ret and returning true if it is. This is meant to be
// used with the following two common utility functions.
#define CHECK_STR_EQ(input, target, ret, output) { \
    strcmp_s(input, strlen(target), target, &ind); \
    if (ind == 0) { \
        *output = ret; \
        return true; \
    } \
}

bool parse_log_level(const char* log_lvl_str, log_lvl_t* log_lvl) {
    int ind = 0;

    // Check against all log levels
    CHECK_STR_EQ(log_lvl_str, "DEBUG", LOG_LVL_DEBUG, log_lvl);
    CHECK_STR_EQ(log_lvl_str, "INFO", LOG_LVL_INFO, log_lvl);
    CHECK_STR_EQ(log_lvl_str, "WARN", LOG_LVL_WARN, log_lvl);
    CHECK_STR_EQ(log_lvl_str, "ERROR", LOG_LVL_ERROR, log_lvl);

    // If this is reached, it means none of the log levels returned, therefore
    // this is an error and an unknown log level string.
    LOG_ERROR("Unknown log level: %s", log_lvl_str);
    return false;
}

bool parse_sched_policy(const char* sched_policy_str, int* sched_policy) {
    int ind = 0;

    // Check against all log levels
    CHECK_STR_EQ(sched_policy_str, "SCHED_OTHER", SCHED_OTHER, sched_policy);
    CHECK_STR_EQ(sched_policy_str, "SCHED_IDLE", SCHED_IDLE, sched_policy);
    CHECK_STR_EQ(sched_policy_str, "SCHED_BATCH", SCHED_BATCH, sched_policy);
    CHECK_STR_EQ(sched_policy_str, "SCHED_FIFO", SCHED_FIFO, sched_policy);
    CHECK_STR_EQ(sched_policy_str, "SCHED_RR", SCHED_RR, sched_policy);

    // If this is reached, it means none of the known scheduler policies were
    // returned, therefore this is an error and an unknown scheduler policy
    // string.
    LOG_ERROR("Unknown Linux scheduler policy: %s", sched_policy_str);
    return false;
}
