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
 * @brief Configuration utilities implementation
 */

#include "eii/zmqbroker/config.h"

namespace eii {
namespace zmqbroker {

/**
* Internal private structure for the wrapping of the app configuration
*/
typedef struct {
    config_t* msgbus_config;
    config_manager::AppCfg* app_cfg;
} broker_conf_t;

// Prototypes
static void free_broker_conf(void* varg);
static config_value_t* get_broker_conf_value(const void*, const char*);

config_t* wrap_appcfg(config_manager::AppCfg* cfg) {
    broker_conf_t* conf = (broker_conf_t*) malloc(sizeof(broker_conf_t));
    if (conf == NULL) {
        LOG_ERROR_0("Failed to malloc broker config");
        return NULL;
    }

    try {
        conf->app_cfg = cfg;
        conf->msgbus_config = cfg->getMsgBusConfig();
        if (conf->msgbus_config == NULL) {
            throw "Failed to retrieve msgbus configuration";
        }

        config_t* config = config_new(
                (void*) conf, free_broker_conf, get_broker_conf_value, NULL);
        if (config == NULL) {
            throw "Failed to initialize config_t for broker config";
        }

        return config;
    } catch (...) {
        if (conf != NULL) {
            if (conf->msgbus_config != NULL) {
                config_destroy(conf->msgbus_config);
            }
        }

        // Re-throw exception
        throw;
    }
}

static void free_broker_conf(void* varg) {
    // Return if the void pointer is NULL
    if (varg == NULL) {
        return;
    }

    broker_conf_t* conf = (broker_conf_t*) varg;
    config_destroy(conf->msgbus_config);

    delete conf->app_cfg;

    free(conf);
}

static config_value_t* get_broker_conf_value(
        const void* varg, const char* key) {
    // Cast void arg to c broker_conf_t value
    const broker_conf_t* conf = (const broker_conf_t*) varg;

    // First attempt to retrieve value from the message bus configuration
    config_value_t* cvt = config_get(conf->msgbus_config, key);

    // If the config value is NULL, i.e. is not in the msgbus_config, then
    // attempt to retrieve it from the service's interfaces configuration in
    // the ConfigMgr
    if (cvt == NULL) {
        try {
            // TODO(kmidkiff): Need to not strip const from key...
            cvt = conf->app_cfg->getInterfaceValue((char*) key);
        } catch (...) {
            // Ignore the exception... This just means it was unable to get
            // the configuration value, let the application deal with it
            cvt = NULL;
        }
    }

    return cvt;
}

}  // namespace zmqbroker
}  // namespace eii
