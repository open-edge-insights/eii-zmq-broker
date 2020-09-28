
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
 * @brief EIS ZeroMQ Broker socket wrapper
 */

#ifndef EIS_ZMQ_BROKER_INCLUDE_EIS_ZMQBROKER_SOCKET_H_
#define EIS_ZMQ_BROKER_INCLUDE_EIS_ZMQBROKER_SOCKET_H_

#include <eis/utils/config.h>
#include <string>

namespace eis {
namespace zmqbroker {

class Socket {
 private:
    // ZeroMQ socket wrapped by this class
    void* m_zmq_socket;

    // ZeroMQ monitor socket for the underlying TCP or IPC socket
    void* m_monitor_socket;

    // Flag for if the socket is TCP or IPC
    bool m_is_tcp;

    // Socket configuration
    config_t* m_config;

    // URI used for binding the socket
    std::string m_uri;

    // Underlying socket type (ZMQ_XSUB or ZMQ_XPUB)
    int m_socket_type;

 public:
    /**
     * Constructor
     *
     * @param zmq_ctx - ZeroMQ context to use when creating the socket
     * @param config  - Socket configuration
     * @param socket_type - ZeroMQ socket type (must be ZMQ_XPUB or ZMQ_XSUB)
     */
    Socket(void* zmq_ctx, config_t* config, int socket_type);

    /**
     * Destructor
     */
    ~Socket();

    /**
     * Check if the socket is a TCP socket.
     *
     * @return bool
     */
    bool is_tcp();

    /**
     * Get the underlying ZeroMQ socket pointer
     *
     * @return void*
     */
    void* get_socket();
};

}  // namespace zmqbroker
}  // namespace eis

#endif  // EIS_ZMQ_BROKER_INCLUDE_EIS_ZMQBROKER_SOCKET_H_
