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
 * @brief EIS ZeroMQ Broker socket wrapper implementation
 */

#include <safe_lib.h>
#include <zmq.h>
#include <eis/utils/logger.h>
#include <sstream>
#include <cstring>
#include "eis/zmqbroker/socket.h"
#include "eis/zmqbroker/common.h"

// Defines
#define CVT_TYPE              "type"
#define CVT_SOCK_DIR          "socket_dir"
#define CVT_SOCK_FILE         "socket_file"
#define CVT_SERVER_SECRET_KEY "server_secret_key"
#define CVT_HOST              "host"
#define CVT_PORT              "port"
#define CVT_RCV_HWM           "zmq_recv_hwm"
#define CVT_SND_HWM           "zmq_send_hwm"
#define CVT_XPUB_NODROP       "zmq_xpub_nodrop"
#define CVT_FRONTEND          ""
#define CVT_TCP_PUBLISH       "zmq_tcp_publish"
#define ZMQ_TCP               "zmq_tcp"
#define ZMQ_IPC               "zmq_ipc"

// Macros
#define ZMQ_SETSOCKOPT(socket, sockopt, value, size) \
{ \
    LOG_DEBUG_0("Setting socket option: "#sockopt); \
    int ret = zmq_setsockopt(socket, sockopt, value, size); \
    if (ret != 0) { \
        LOG_ZMQ_ERROR("Failed to set "#sockopt); \
        throw "Failed to set "#sockopt; \
    } \
}

#define CVT_DESTROY(cvt) \
    if (cvt != NULL) { \
        config_value_destroy(cvt); \
        cvt = NULL; \
    }

namespace eis {
namespace zmqbroker {

// Helper function prototypes
static std::string create_ipc_uri(config_t* config, const char* key);
static std::string create_tcp_uri(config_t* config, const char* key);

Socket::Socket(void* zmq_ctx, config_t* config, int socket_type) :
    m_zmq_socket(NULL), m_monitor_socket(NULL), m_is_tcp(false),
    m_config(config), m_socket_type(socket_type) {
    config_value_t* cvt_type = NULL;
    config_value_t* cvt_topic = NULL;
    config_value_t* cvt_secret_key = NULL;
    config_value_t* cvt_xpub_nodrop = NULL;
    config_value_t* cvt_snd_hwm = NULL;
    config_value_t* cvt_rcv_hwm = NULL;

    // Constant char* for the topic name inside of the cnofig_t depending on
    // whether or not the socket type is ZMQ_XSUB or ZMQ_XPUB (note: a check is
    // done later to assert that the socket_type is one of those two)
    const char* key = CVT_FRONTEND;

    try {
        LOG_DEBUG_0("Getting socket type");
        cvt_type = config_get(config, CVT_TYPE);
        if (cvt_type == NULL) {
            throw "Configuration missing \"type\" key";
        } else if (cvt_type->type != CVT_STRING) {
            throw "\"type\" key must be a string";
        }

        const char* type = cvt_type->body.string;
        int ind_ipc = 0;
        int ind_tcp = 0;
        strcmp_s(type, strlen(ZMQ_IPC), ZMQ_IPC, &ind_ipc);
        strcmp_s(type, strlen(ZMQ_TCP), ZMQ_TCP, &ind_tcp);

        if (ind_ipc == 0) {
            LOG_DEBUG_0("Creating an IPC socket");
            m_uri = create_ipc_uri(config, key);
        } else if (ind_tcp == 0) {
            LOG_DEBUG_0("Creating a TCP socket");
            m_is_tcp = true;

            // If the socket is a TCP socket and is the backend, i.e. is a
            // ZMQ_XPUB socket, then the configuration for the host/port will
            // be under the "zmq_tcp_publish" key and not "backend". This is a
            // result of using the msgbus configuration structure rather than
            // a custom configuration structure for the interface
            if (socket_type == ZMQ_XPUB) {
                key = CVT_TCP_PUBLISH;
            }

            m_uri = create_tcp_uri(config, key);
        } else {
            throw "Unknown socket type";
        }

        LOG_DEBUG_0("Creating ZeroMQ socket");
        m_zmq_socket = zmq_socket(zmq_ctx, socket_type);
        if (m_zmq_socket == NULL) {
            LOG_ZMQ_ERROR("Failed to initialize ZeroMQ socket");
            throw "Failed to initialize ZeroMQ socket";
        }

        // Set the various socket options required for the ZeroMQ sockets

        // Integer value which will be reused for setting various integer
        // valued options
        int value = 0;

        // Set ZMQ_LINGER to 0
        ZMQ_SETSOCKOPT(m_zmq_socket, ZMQ_LINGER, &value, sizeof(value));

        // Check if is TCP and set various socket options as a result
        if (m_is_tcp) {
            // Check if a curve server key was provided, if it was make the
            // socket a curve server with that secret key - note that the topic
            // only ever exists in the configuration if the secret key is there
            // since the code retrieves it's endpoint from the config manager
            // style of configuration
            cvt_topic = config_get(config, key);
            if (cvt_topic != NULL) {
                // Verify the topic configuration value is an object
                if (cvt_topic->type != CVT_OBJECT) {
                    throw "Topic in configuration must be an object";
                }

                // Retrieve the secret key from the topic configuration
                cvt_secret_key = config_value_object_get(
                        cvt_topic, CVT_SERVER_SECRET_KEY);
                if (cvt_secret_key != NULL) {
                    // It is okay that the key not exist here, because in
                    // the message bus configuration the zmq_tcp_publish or
                    // the empty string ("") key will be there with the host
                    // and port, but no secret key. This just means we are
                    // running without authentication.

                    // Verify it is a string
                    if (cvt_secret_key->type != CVT_STRING) {
                        throw "Server secret key must be a string";
                    }

                    // Make the socket use CurveZMQ encryption and ZAP
                    // authentication
                    value = 1;
                    ZMQ_SETSOCKOPT(
                            m_zmq_socket, ZMQ_CURVE_SERVER, &value,
                            sizeof(value));

                    // Add the server secret key to the socket
                    ZMQ_SETSOCKOPT(m_zmq_socket, ZMQ_CURVE_SECRETKEY,
                                   cvt_secret_key->body.string, 40);
                }
            }
        }

        // Set XSUB socket specific socket options
        if (socket_type == ZMQ_XSUB) {
            LOG_DEBUG_0("Setting XSUB specific socket options");

            // Set the receive high watermark, if it is provided in the config
            cvt_rcv_hwm = config_get(config, CVT_RCV_HWM);
            if (cvt_rcv_hwm != NULL) {
                if (cvt_rcv_hwm->type != CVT_INTEGER) {
                    throw "Receive HWM must be an insteger";
                }

                // Casting from int64_t to int, because ZeroMQ expects an int
                int rcv_hwm = static_cast<int>(cvt_rcv_hwm->body.integer);
                LOG_DEBUG("Setting XSUB recv HWM to: %d", rcv_hwm);
                ZMQ_SETSOCKOPT(
                        m_zmq_socket, ZMQ_RCVHWM, &rcv_hwm, sizeof(rcv_hwm));
            }
        } else if (socket_type == ZMQ_XPUB) {
            LOG_DEBUG_0("Setting XPUB specific socket options");

            cvt_snd_hwm = config_get(config, CVT_SND_HWM);
            if (cvt_snd_hwm != NULL) {
                if (cvt_snd_hwm->type != CVT_INTEGER) {
                    throw "Send HWM must be an integer";
                }

                // Casting from int64_t to int, because ZeroMQ expects an int
                int snd_hwm = static_cast<int>(cvt_snd_hwm->body.integer);
                LOG_DEBUG("Setting XPUB send HWM to: %d", snd_hwm);
                ZMQ_SETSOCKOPT(
                        m_zmq_socket, ZMQ_SNDHWM, &snd_hwm, sizeof(snd_hwm));
            }

            cvt_xpub_nodrop = config_get(config, CVT_XPUB_NODROP);
            if (cvt_xpub_nodrop != NULL) {
                if (cvt_xpub_nodrop->type != CVT_BOOLEAN) {
                    throw "XPUB nodrop must be a boolean";
                }

                // If the XPUB nodrop is set to true, then set the value for
                // the socket option to 1, otherwise set it to 0
                value = (cvt_xpub_nodrop->body.boolean) ? 1 : 0;

                ZMQ_SETSOCKOPT(
                        m_zmq_socket, ZMQ_XPUB_NODROP, &value, sizeof(value));
            }
        } else {
            throw "Sockets can only be ZMQ_XPUB or ZMQ_XSUB";
        }

        LOG_DEBUG("Binding socket to: %s", m_uri.c_str());
        int rc = zmq_bind(m_zmq_socket, m_uri.c_str());
        if (rc != 0) {
            LOG_ZMQ_ERROR("Failed to bind socket");
            throw "Failed to bind socket";
        }

        // Clean up retrieved config value memory
        CVT_DESTROY(cvt_type);
        CVT_DESTROY(cvt_topic);
        CVT_DESTROY(cvt_secret_key);
        CVT_DESTROY(cvt_xpub_nodrop);
        CVT_DESTROY(cvt_snd_hwm);
        CVT_DESTROY(cvt_rcv_hwm);
    } catch (...) {
        LOG_DEBUG_0("Cleaning up after exception");

        // Clean up retrieved config value memory in the error case
        CVT_DESTROY(cvt_type);
        CVT_DESTROY(cvt_topic);
        CVT_DESTROY(cvt_secret_key);
        CVT_DESTROY(cvt_xpub_nodrop);
        CVT_DESTROY(cvt_snd_hwm);
        CVT_DESTROY(cvt_rcv_hwm);

        // Close the ZeroMQ socket if it was initialized prior to the excepton
        if (m_zmq_socket != NULL) {
            zmq_close(m_zmq_socket);
        }

        // Re-throw the same exception
        throw;
    }
}

Socket::~Socket() {
    LOG_DEBUG("Closing socket %s", m_uri.c_str());
    if (m_zmq_socket != NULL)
        zmq_close(m_zmq_socket);

    LOG_DEBUG_0("Deleting socket configuration");
    config_destroy(m_config);
}

bool Socket::is_tcp() { return m_is_tcp; }

void* Socket::get_socket() { return m_zmq_socket; }

static std::string create_ipc_uri(config_t* config, const char* key) {
    std::ostringstream os;

    // Add initial part of the URI
    os << "ipc://";

    // Get EndPoint object
    config_value_t* cvt_endpoint = config_get(config, key);
    if (cvt_endpoint == NULL) {
        throw std::runtime_error("Config missing key: " + std::string(key));
    } else if (cvt_endpoint->type != CVT_OBJECT) {
        config_value_destroy(cvt_endpoint);
        throw std::runtime_error(
                "Key, \"" + std::string(key) + "\" must be an object");
    }

    // Get socket directory
    config_value_t* cvt_sock_dir = config_get(config, CVT_SOCK_DIR);
    if (cvt_sock_dir == NULL) {
        config_value_destroy(cvt_endpoint);
        throw std::runtime_error(
                "Config missing key: " + std::string(CVT_SOCK_DIR));
    } else if (cvt_sock_dir->type != CVT_STRING) {
        config_value_destroy(cvt_sock_dir);
        config_value_destroy(cvt_endpoint);
        throw "Socket directory must be a string";
    }

    os << cvt_sock_dir->body.string << "/";
    config_value_destroy(cvt_sock_dir);

    // Get the config object associated with the topic to obtain the socket
    // file
    config_value_t* cvt_sock_file = config_value_object_get(
            cvt_endpoint, CVT_SOCK_FILE);

    // Check that the socket file is correct
    if (cvt_sock_file == NULL) {
        config_value_destroy(cvt_endpoint);
        throw std::runtime_error(
                "Config missing key: " + std::string(CVT_SOCK_FILE));
    } else if (cvt_sock_file->type != CVT_STRING) {
        config_value_destroy(cvt_sock_file);
        config_value_destroy(cvt_endpoint);
        throw "Socket file must be a string";
    }

    os << cvt_sock_file->body.string;
    config_value_destroy(cvt_sock_file);
    config_value_destroy(cvt_endpoint);

    return os.str();
}

static std::string create_tcp_uri(config_t* config, const char* key) {
    std::ostringstream os;

    // Add initial part of the URI
    os << "tcp://";

    // Get EndPoint object
    config_value_t* cvt_endpoint = config_get(config, key);
    if (cvt_endpoint == NULL) {
        throw std::runtime_error(
                "Config missing key: " + std::string(key));
    } else if (cvt_endpoint->type != CVT_OBJECT) {
        config_value_destroy(cvt_endpoint);
        throw std::runtime_error(
                "Key, \"" + std::string(key) + "\" must be an object");
    }

    // Extract Host
    config_value_t* cvt_host = config_value_object_get(cvt_endpoint, CVT_HOST);
    if (cvt_host == NULL) {
        config_value_destroy(cvt_endpoint);
        throw std::runtime_error(
                "Config missing key: " + std::string(CVT_HOST));
    } else if (cvt_host->type != CVT_STRING) {
        config_value_destroy(cvt_host);
        config_value_destroy(cvt_endpoint);
        throw "Host configuration value must be a sting";
    }

    os << cvt_host->body.string << ":";
    config_value_destroy(cvt_host);

    // Extract Port
    config_value_t* cvt_port = config_value_object_get(cvt_endpoint, CVT_PORT);
    if (cvt_port == NULL) {
        config_value_destroy(cvt_endpoint);
        throw std::runtime_error(
                "Config missing key: " + std::string(CVT_PORT));
    } else if (cvt_port->type != CVT_INTEGER) {
        config_value_destroy(cvt_port);
        config_value_destroy(cvt_endpoint);
        throw "Port configuration value must be an integer";
    }

    os << cvt_port->body.integer;
    config_value_destroy(cvt_port);

    // Destroy endpoint object, since we are done with it
    config_value_destroy(cvt_endpoint);

    return os.str();
}

}  // namespace zmqbroker
}  // namespace eis
