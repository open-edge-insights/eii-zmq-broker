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
 * @brief EIS ZeroMQ Broker main entrypoint
 */

#include <unistd.h>
#include <csignal>
#include <eis/utils/json_config.h>
#include <eis/config_manager/config_mgr.hpp>
#include "eis/zmqbroker/broker.h"
#include "eis/zmqbroker/common.h"
#include "eis/zmqbroker/config.h"

// Globals
eis::zmqbroker::Broker* g_broker = NULL;

/**
 * Signal handler to tell the broker to stop running when SIGTERM or SIGINT
 * are received.
 */
static void signal_handler(int signo) {
    if (g_broker != NULL) {
        g_broker->stop();
    }
}

// TODO(kmidkiff): Add callback for receiving updated configs from the config
// manager

int main(int argc, char** argv) {
    // Configuration values to be used later
    eis::config_manager::ConfigMgr* cfgmgr = NULL;
    config_t* frontend_config = NULL;
    config_t* backend_config = NULL;

    // Setup signal handlers
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    // Command line parsing
    if (argc > 1 && argc < 3) {
        LOG_ERROR_0("Too few arguments");
        return -1;
    } else if (argc > 3) {
        LOG_ERROR_0("Too many arguments");
        return -1;
    } else if (argc == 1) {
        // Reading the configuration using the EIS ConfigMgr APIs
        LOG_DEBUG_0("Initializing configuration manager");
        cfgmgr = new eis::config_manager::ConfigMgr();

        eis::config_manager::SubscriberCfg* frontend =
            cfgmgr->getSubscriberByName("frontend");
        if (frontend == NULL) {
            LOG_ERROR_0("Sub config NULL");
            delete cfgmgr;
            return -1;
        }

        // frontend_config = frontend->getMsgBusConfig();
        frontend_config = eis::zmqbroker::wrap_appcfg(frontend);
        if (frontend_config == NULL) {
            LOG_ERROR_0("Failed to get config_t for frontend config");
            delete cfgmgr;
            return -1;
        }

        eis::config_manager::PublisherCfg* backend =
            cfgmgr->getPublisherByName("backend");
        if (backend == NULL) {
            LOG_ERROR_0("Failed to get backend publisher config");
            delete cfgmgr;
            config_destroy(frontend_config);
            return -1;
        }

        // backend_config = backend->getMsgBusConfig();
        backend_config = eis::zmqbroker::wrap_appcfg(backend);
        if (backend_config == NULL) {
            LOG_ERROR_0("Failed to get config_t for backend config");
            delete cfgmgr;
            config_destroy(frontend_config);
            return -1;
        }
    } else {
        LOG_INFO("Loading frontend JSON config: %s", argv[1]);
        frontend_config = json_config_new(argv[1]);
        if (frontend_config == NULL) {
            LOG_ERROR("Failed to load JSON config: %s", argv[1]);
            return -1;
        }

        LOG_INFO("Loading backend JSON config: %s", argv[2]);
        backend_config = json_config_new(argv[2]);
        if (backend_config == NULL) {
            LOG_ERROR("Failed to load JSON config: %s", argv[2]);
            return -1;
        }
    }

    // TODO(kmidkiff): This should be dynamic...
    set_log_level(LOG_LVL_DEBUG);

    try {
        LOG_INFO_0("Initializing broker");
        g_broker = new eis::zmqbroker::Broker(frontend_config, backend_config);

        LOG_INFO_0("Broker running...");
        int rc = g_broker->run_forever();
        LOG_INFO("Broker exited (rc: %d)", rc);
    } catch (const char* ex) {
        LOG_ERROR("Error in broker: %s", ex);
    }

    if (g_broker != NULL) {
        delete g_broker;
        g_broker = NULL;
    }
    if (cfgmgr != NULL) {
        delete cfgmgr;
        cfgmgr = NULL;
    }

    LOG_DEBUG_0("Done.");

    return 0;
}
