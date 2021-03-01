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
 * @brief ZeroMQ Broker
 */

#ifndef ZMQ_BROKER_INCLUDE_ZMQBROKER_BROKER_H_
#define ZMQ_BROKER_INCLUDE_ZMQBROKER_BROKER_H_

#include <eii/utils/config.h>
#include <atomic>
#include "eii/zmqbroker/zap.h"
#include "eii/zmqbroker/socket.h"

namespace eii {
namespace zmqbroker {

class Broker {
 private:
    // ZeroMQ context
    void* m_zmq_ctx;

    // Frontend ZMQ_XSUB socket
    Socket* m_frontend;

    // Backend ZMQ_XPUB socket
    Socket* m_backend;

    // ZAP context
    zap_ctx_t* m_zap_ctx;

    // Broker thread scheduling policy
    int m_sched_policy;

    // Broker thread scheduler priority (depends on the scheduling policy)
    int m_sched_priority;

 public:
    /**
     * Constructor
     *
     * \note sched_policy and sched_priority must be values as defined in the
     *  SCHED section of the Linux Programmer's Manual (see
     *  https://man7.org/linux/man-pages/man7/sched.7.html for more details).
     *
     * @param frontend_config - Frontend XSUB socket configuration
     * @param backend_config  - Backend XPUB socket configuration
     * @param sched_policy - Broker thread linux scheduler policy
     * @param sched_priority - Broker thread Linux scheduler priority
     *  (dependent on sched_policy to be valid)
     */
    Broker(config_t* frontend_config, config_t* backend_config,
           int sched_policy=-1, int sched_priority=-1);

    /**
     * Destructor
     */
    ~Broker();

    /**
     * Start running the broker until the stop flag is set.
     *
     * @return 0 if exited successfully, less than 0 if an error ocurred
     */
    int run_forever();

    /**
     * Close the underlying ZeroMQ sockets and terminate the ZeroMQ context
     * in order to stop the @c Broker::run_forever() method.
     */
    void stop();
};

}  // namespace zmqbroker
}  // namespace eii

#endif  // ZMQ_BROKER_INCLUDE_ZMQBROKER_BROKER_H_
