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
 * @brief EIS ZeroMQ Broker class implementation
 */

#include <safe_lib.h>
#include <zmq.h>
#include <stdlib.h>
#include <unistd.h>
#include <eis/utils/logger.h>
#include <vector>
#include <cassert>
#include <string>
#include <cstring>
#include "eis/zmqbroker/common.h"
#include "eis/zmqbroker/broker.h"

// Defines
#define CVT_ALLOWED_CLIENTS "AllowedClients"

namespace eis {
namespace zmqbroker {

// Helper function prototypes
static void extract_allowed_clients(
        std::vector<std::string>* allowed_clients, config_t* config);
static config_value_t* vec_get_config_value(const void* o, const char* key);
static config_value_t* vec_get_array_item(const void* array, int idx);
static void vec_free(void* varp);

Broker::Broker(config_t* frontend_config, config_t* backend_config) :
    m_zmq_ctx(NULL), m_frontend(NULL), m_backend(NULL), m_zap_ctx(NULL) {
    try {
        // Initialize ZeroMQ context
        m_zmq_ctx = zmq_ctx_new();
        if (m_zmq_ctx == NULL) {
            throw "Failed to initialize ZeroMQ context";
        }

        // Initialize ZeroMQ broker frontend socket
        m_frontend = new Socket(m_zmq_ctx, frontend_config, ZMQ_XSUB);

        // Initialize ZeroMQ broker backend socket
        m_backend = new Socket(m_zmq_ctx, backend_config, ZMQ_XPUB);

        // If one of the sockets is TCP, then check if there are allowed client
        // lists and start the ZAP authentication thread
        if (m_backend->is_tcp() || m_frontend->is_tcp()) {
            std::vector<std::string>* allowed_clients =
                new std::vector<std::string>();

            if (m_frontend->is_tcp()) {
                extract_allowed_clients(allowed_clients, frontend_config);
            }

            if (m_backend->is_tcp()) {
                extract_allowed_clients(allowed_clients, backend_config);
            }

            // If the list of allowed clients is not empty, then start the
            // ZAP thread
            if (!allowed_clients->empty()) {
                LOG_DEBUG_0("Starting ZAP authentication");
                config_t* zap_config = config_new(
                        static_cast<void*>(allowed_clients), vec_free,
                        vec_get_config_value);
                if (zap_config == NULL) {
                    throw "Failed to initialize ZAP config_t";
                }

                int rc = zap_initialize(m_zmq_ctx, zap_config, &m_zap_ctx);
                if (rc < 0) {
                    config_destroy(zap_config);
                    throw "Failed to initialize ZAP";
                }

                config_destroy(zap_config);
            } else {
                LOG_WARN_0("ZAP authentication disabled");
            }

            delete allowed_clients;
        }
    } catch (...) {
        LOG_DEBUG_0("Cleaning up after exception");

        // Clean up memory in the error case
        if (m_frontend != NULL) {
            delete m_frontend;
        } else {
            // Ownership of the config still lies with the broker at this point
            config_destroy(frontend_config);
        }

        if (m_backend != NULL) {
            delete m_backend;
        } else {
            // Ownership of the config still lies with the broker at this point
            config_destroy(backend_config);
        }

        if (m_zap_ctx != NULL) {
            zap_destroy(m_zap_ctx);
        }

        if (m_zmq_ctx != NULL) {
            zmq_ctx_term(m_zmq_ctx);
        }

        throw;  // Re-throw the exception
    }
}

Broker::~Broker() {
    LOG_DEBUG_0("In broker destructor");

    LOG_DEBUG_0("Deleting frontend socket");
    if (m_frontend != NULL)  delete m_frontend;

    LOG_DEBUG_0("Deleting backend socket");
    if (m_backend != NULL)  delete m_backend;

    if (m_zap_ctx != NULL) {
        LOG_DEBUG_0("Stopping ZAP");
        zap_destroy(m_zap_ctx);
    }

    LOG_DEBUG_0("Terminating ZeroMQ context");
    if (m_zmq_ctx != NULL)  zmq_ctx_term(m_zmq_ctx);
}

int Broker::run_forever() {
    if (m_frontend == NULL || m_backend == NULL || m_zmq_ctx == NULL) {
        throw "The broker has already been ran and stopped";
    }

    int rc = 0;
    void* frontend = m_frontend->get_socket();
    void* backend = m_backend->get_socket();

    LOG_DEBUG_0("Started running forever");
    rc = zmq_proxy(frontend, backend, NULL);
    LOG_DEBUG("Proxy stopped, rc = %d", rc);
    if (rc != 0)
        LOG_ZMQ_ERROR("Proxy function encountered an error");

    return rc;
}

void Broker::stop() {
    // Delete sockets
    if (m_frontend != NULL) {
        delete m_frontend;
        m_frontend = NULL;
    }

    if (m_backend != NULL) {
        delete m_backend;
        m_backend = NULL;
    }

    if (m_zap_ctx != NULL) {
        zap_destroy(m_zap_ctx);
        m_zap_ctx = NULL;
    }

    // Terminate ZeroMQ context
    if (m_zmq_ctx != NULL) {
        zmq_ctx_term(m_zmq_ctx);
        m_zmq_ctx = NULL;
    }
}

/**
 * Helper function to extract the keys in the allowed clients list into the
 * provided vector.
 *
 * @param allowed_clients - Output vector to push keys onto
 * @param config          - Config with the allowed_clients key
 */
static void extract_allowed_clients(
        std::vector<std::string>* allowed_clients, config_t* config) {
    config_value_t* cvt_allowed_clients = NULL;
    config_value_t* cvt_key = NULL;

    try {
        cvt_allowed_clients = config_get(
                config, CVT_ALLOWED_CLIENTS);
        if (cvt_allowed_clients == NULL) {
            LOG_WARN_0("No allowed clients");
            return;
        } else if (cvt_allowed_clients->type != CVT_ARRAY) {
            config_value_destroy(cvt_allowed_clients);
            throw "Allowed clients must be an array";
        }

        config_value_array_t* arr = cvt_allowed_clients->body.array;
        int len = static_cast<int>(arr->length);

        for (int i = 0; i < len; i++) {
            // Obtain key from the array of allowed clients
            cvt_key = arr->get(arr->array, i);
            if (cvt_key == NULL) {
                throw "Failed to get array element";
            } else if (cvt_key->type != CVT_STRING) {
                throw "Allowed client keys must be strings";
            } else if (!verify_key_len(cvt_key->body.string)) {
                throw "Incorrect key length, must be 40 characters";
            }

            // Convert the char* for the key to a string
            std::string key(cvt_key->body.string);

            // Push the key into the list of allowed clients
            allowed_clients->push_back(key);

            // Destroy the retrieved value from the array
            config_value_destroy(cvt_key);
        }

        // Clean up memory in non-error case
        config_value_destroy(cvt_allowed_clients);
    } catch (...) {
        // Clean up memory in error case
        config_value_destroy(cvt_allowed_clients);

        if (cvt_key != NULL) {
            config_value_destroy(cvt_key);
        }

        // Re-throw exception
        throw;
    }
}

/**
 * Helper specifically for providing the ZAP thread access to the elements in
 * the allowed clients vector.
 */
static config_value_t* vec_get_config_value(const void* o, const char* key) {
    config_value_t* cvt = NULL;

    int ind_key = 0;
    strcmp_s(key, strlen(CVT_ALLOWED_CLIENTS), CVT_ALLOWED_CLIENTS, &ind_key);

    if (ind_key != 0) {
        LOG_ERROR("Vector config_t only supports %s, not %s",
                  CVT_ALLOWED_CLIENTS, key);
        return NULL;
    }

    std::vector<std::string>* arr = (std::vector<std::string>*) o;
    cvt = config_value_new_array(
            static_cast<void*>(arr), arr->size(), vec_get_array_item, NULL);
    if (cvt == NULL) {
        LOG_ERROR_0("Failed to initalize new config array");
    }

    return cvt;
}

/**
 * Helper for retrieving an element out of the vector of allowed_clients.
 */
static config_value_t* vec_get_array_item(const void* array, int idx) {
    // Cast array to vector
    std::vector<std::string>* arr = (std::vector<std::string>*) array;

    if (idx >= static_cast<int>(arr->size())) {
        LOG_ERROR("Index %d out of range", idx);
        return NULL;
    }

    // Get the string
    std::string key_str = arr->at(idx);

    // Create and return the configuration value
    return config_value_new_string(key_str.c_str());
}

/**
 * Empty free function, because the vector will be freed when the program
 * leaves the constructor's scope.
 */
static void vec_free(void* varp) { }

}  // namespace zmqbroker
}  // namespace eis
