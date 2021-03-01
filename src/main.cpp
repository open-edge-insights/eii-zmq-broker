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
 * @brief ZeroMQ Broker main entrypoint
 */

#include <stdlib.h>
#include <stdio.h>
#include <eii/utils/json_config.h>
#include <unistd.h>
#include <atomic>
#include <csignal>
#include <eii/config_manager/config_mgr.hpp>
#include "eii/zmqbroker/broker.h"
#include "eii/zmqbroker/common.h"
#include "eii/zmqbroker/config.h"

// Defines
#define C_LOG_LEVEL        "C_LOG_LEVEL"
#define SCHED_POLICY       "SCHED_POLICY"
#define SCHED_PRIORITY     "SCHED_PRIORITY"
#define CVT_SCHED_POLICY   "sched_policy"
#define CVT_SCHED_PRIORITY "sched_priority"

// Globals
eii::zmqbroker::Broker* g_broker = NULL;
int g_sched_policy = -1;
int g_sched_priority = -1;
std::atomic<bool> g_config_changed(false);

/**
 * Signal handler to tell the broker to stop running when SIGTERM or SIGINT
 * are received.
 */
static void signal_handler(int signo) {
    if (g_broker != NULL) {
        g_broker->stop();
    }
}

/**
 * Helper function to extract the configuration values for the broker
 * out of a @c config_t structure.
 *
 * \note This function throws exceptions if the configuration values are
 *  invalid.
 *
 * @param config - Configuration from which to extract values
 */
static void extract_config(config_t* config) {
    config_value_t* cvt_sched_policy = NULL;
    config_value_t* cvt_sched_priority = NULL;

    // Obtain the scheduler policy if it is set and verify the configuration
    cvt_sched_policy = config_get(config, CVT_SCHED_POLICY);
    if (cvt_sched_policy != NULL) {
        if (cvt_sched_policy->type != CVT_STRING) {
            config_value_destroy(cvt_sched_policy);
            throw "Schedule policy must be a string";
        } else if (!parse_sched_policy(
                    cvt_sched_policy->body.string, &g_sched_policy)) {
            config_value_destroy(cvt_sched_policy);
            throw "Failed to parse linux scheduler policy";
        }
        config_value_destroy(cvt_sched_policy);
    }

    // Obtain the scheduler priority if it is set and verify the configuration
    cvt_sched_priority = config_get(config, CVT_SCHED_PRIORITY);
    if (cvt_sched_priority != NULL) {
        if (cvt_sched_priority->type != CVT_INTEGER) {
            config_value_destroy(cvt_sched_priority);
            throw "Scheduler priority must be an integer";
        } else if (cvt_sched_priority->body.integer < 0
                || cvt_sched_priority->body.integer > 99) {
            config_value_destroy(cvt_sched_priority);
            throw "Scheduler priority must be in the range (0, 99)";
        }
        g_sched_priority = cvt_sched_priority->body.integer;
        config_value_destroy(cvt_sched_priority);
    }
}

/**
 * Callback for when the broker's configuration has changed.
 */
static void on_config_change(
        const char* key, config_t* value, void* user_data) {
    try {
        LOG_DEBUG_0("Received configuration update, extracting changes");
        extract_config(value);

        // Set the config changed flag
        g_config_changed.store(true);

        LOG_DEBUG_0("Successfully extracted configuration values, "
                    "restarting broker");
        g_broker->stop();
    } catch (const char* ex) {
        LOG_ERROR("Failed updating config (keeping running as is): %s", ex);
    }
}

/**
 * Helper function to extract the log level from the C_LOG_LEVEL environmental
 * variable.
 *
 * @return true if successfully applied log level, otherwise false
 */
static bool set_app_log_level() {
    // Get and set the log level (if the environmental variable is set)
    char* log_lvl_str = getenv(C_LOG_LEVEL);
    if (log_lvl_str != NULL) {
        log_lvl_t log_lvl;
        if (parse_log_level(log_lvl_str, &log_lvl)) {
            set_log_level(log_lvl);
        } else {
            return false;
        }
    } else {
        // Defaulting to error log level
        set_log_level(LOG_LVL_ERROR);
    }
    return true;
}

/**
 * Print the CLI usage to stderr.
 *
 * @param name - Name of the binary
 */
static void usage(const char* name) {
    fprintf(stderr, "usage: %s [-h|--help] [<frontend-config> "
            "<backend-config>]\n", name);
    fprintf(stderr, "\t-h|--help         - Show this help\n");
    fprintf(stderr, "\t<frontend-config> - (Optional) Frontend XSUB JSON "
            "config\n");
    fprintf(stderr, "\t<backend-config>  - (Optional) Backend XPUB JSON "
            "config\n");
}

int main(int argc, char** argv) {
    // Configuration values to be used later
    int rc = 0;
    eii::config_manager::ConfigMgr* cfgmgr = NULL;
    config_t* frontend_config = NULL;
    config_t* backend_config = NULL;

    // Setup signal handlers
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    // Try to set the log level from the environment. Attempting here so that
    // debugging logging can be enabled if desired for when the broker is
    // initializing it's configuration
    if (!set_app_log_level()) {
        // NOTE: Errors are logged by the set_app_log_level() function
        return -1;
    }

    // Command line parsing
    // Check if -h or --help CLI params have been given
    if (argc > 1) {
        int short_help_ind = 0;
        int help_ind = 0;
        strcmp_s(argv[1], 2, "-h", &short_help_ind);
        strcmp_s(argv[1], 6, "--help", &help_ind);

        if (short_help_ind == 0 || help_ind == 0) {
            usage(argv[0]);
            return 0;  // Not an error, exit with 0 error code...
        }
    }
    // else, continue with normal parsing

    try {
        if (argc > 1 && argc < 3) {
            LOG_ERROR_0("Too few arguments");
            return -1;
        } else if (argc > 3) {
            LOG_ERROR_0("Too many arguments");
            return -1;
        } else if (argc == 1) {
            // Reading the configuration using the EII ConfigMgr APIs
            LOG_DEBUG_0("Initializing configuration manager");
            cfgmgr = new eii::config_manager::ConfigMgr();

            // Obtain the frontend configuration for the XSUB socket
            eii::config_manager::SubscriberCfg* frontend =
                cfgmgr->getSubscriberByName("frontend");
            if (frontend == NULL) {
                LOG_ERROR_0("Sub config NULL");
                delete cfgmgr;
                return -1;
            }

            frontend_config = eii::zmqbroker::wrap_appcfg(frontend);
            if (frontend_config == NULL) {
                LOG_ERROR_0("Failed to get config_t for frontend config");
                delete cfgmgr;
                return -1;
            }

            // Obtain the backend configuration for the XPUB socket
            eii::config_manager::PublisherCfg* backend =
                cfgmgr->getPublisherByName("backend");
            if (backend == NULL) {
                LOG_ERROR_0("Failed to get backend publisher config");
                config_destroy(frontend_config);
                delete cfgmgr;
                return -1;
            }

            backend_config = eii::zmqbroker::wrap_appcfg(backend);
            if (backend_config == NULL) {
                LOG_ERROR_0("Failed to get config_t for backend config");
                config_destroy(frontend_config);
                delete cfgmgr;
                return -1;
            }

            // Obtain the app's configuration
            eii::config_manager::AppCfg* app_cfg = cfgmgr->getAppConfig();
            if (app_cfg == NULL) {
                LOG_ERROR_0("Failed to get app config");
                config_destroy(frontend_config);
                config_destroy(backend_config);
                delete cfgmgr;
                return -1;
            }

            // Obtain the config_t for the app's configuration
            config_t* app_config = app_cfg->getConfig();
            if (app_config == NULL) {
                LOG_ERROR_0("Failed to get app config config_t");
                config_destroy(frontend_config);
                config_destroy(backend_config);
                delete cfgmgr;
                return -1;
            }

            // Extract the configuration values from the application's config
            try {
                extract_config(app_config);
            } catch (const char* err) {
                LOG_ERROR("Failed to extract config values: %s", err);
                config_destroy(frontend_config);
                config_destroy(backend_config);
                delete cfgmgr;
                return -1;
            }

            // Register a watch for the configuration of the broker
            LOG_DEBUG_0("Registering config callback");
            if (!app_cfg->watchConfig(on_config_change, NULL)) {
                LOG_ERROR_0("Failed to register callback");
                config_destroy(frontend_config);
                config_destroy(backend_config);
                delete cfgmgr;
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

            char* sched_policy_str = getenv(SCHED_POLICY);
            if (sched_policy_str != NULL) {
                if (!parse_sched_policy(sched_policy_str, &g_sched_policy)) {
                    config_destroy(backend_config);
                    config_destroy(frontend_config);
                    return -1;
                }
            }

            char* sched_priority_str = getenv(SCHED_PRIORITY);
            if (sched_priority_str != NULL) {
                g_sched_priority = atoi(sched_priority_str);

                // If the sched_priority is not 0, then assume it atoi() parsed
                // the string correctly. Otherwise, if it is 0, then the
                // variable may be configured incorrectly. Confirm that the
                // string value is indeed "0".
                if (g_sched_priority == 0) {
                    int ind = 0;
                    strcmp_s(sched_priority_str, 1, "0", &ind);
                    if (ind != 0) {
                        LOG_ERROR(
                            "Scheduler priority must be an integer not: %s",
                             sched_priority_str);
                        config_destroy(frontend_config);
                        config_destroy(backend_config);
                        return -1;
                    }
                } else if (g_sched_priority < 0 || g_sched_priority > 99) {
                    LOG_ERROR_0(
                            "Schedule priority must be in the range (0, 99)");
                    config_destroy(frontend_config);
                    config_destroy(backend_config);
                    return -1;
                }
            }
        }

        // Get and set the log level (if the environmental variable is set).
        // Re-setting the log level here, since the ConfigMgr may have set it
        // again based on the values in the /GlobalEnv/ configuration.
        if (!set_app_log_level()) {
            // NOTE: Errors are logged by the set_app_log_level() function
            if (frontend_config != NULL) { config_destroy(frontend_config); }
            if (backend_config != NULL) { config_destroy(backend_config); }
            if (cfgmgr != NULL) { delete cfgmgr; }
            return -1;
        }

        while (true) {
            LOG_INFO_0("Initializing broker");
            g_broker = new eii::zmqbroker::Broker(
                    frontend_config, backend_config,
                    g_sched_policy, g_sched_priority);

            LOG_INFO_0("Broker running...");
            int rc = g_broker->run_forever();
            LOG_INFO("(rc: %d) Broker stopped", rc);

            // Only break if the exit was not due to a configuration change
            if (!g_config_changed.load()) {
                break;
            } else {
                // If the configuration was changed, then continue in the loop
                // and reset the flag so future changes can be signaled
                g_config_changed.store(false);
                LOG_INFO_0("Configuration changed - restarting the broker");
            }
        }
    } catch (std::exception& ex) {
        LOG_ERROR("Error in broker: %s", ex.what());
        rc = -1;
    } catch (const char* ex) {
        LOG_ERROR("Error in broker: %s", ex);
        rc = -1;
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

    return rc;
}
