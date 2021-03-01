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
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

/**
 * @brief broker GTests unit tests
 */

#include <pthread.h>
#include <gtest/gtest.h>
#include <eii/msgbus/msgbus.h>
#include <eii/utils/json_config.h>
#include "eii/zmqbroker/broker.h"

// Defines
#define PUB_SUB_TOPIC "broker-tests-topic"

// Macros
#define ASSERT_NOT_NULL(val) { \
    if (val == NULL) FAIL() << #val" should not be NULL"; \
}
#define ASSERT_NULL(val) { \
    if (val != NULL) FAIL() << #val" should be NULL"; \
}

namespace eii {
namespace zmqbroker {

// Helper prototypes
static msg_envelope_t* initialize_message();

// Global for the broker, only to be used by the forked child process, never
// actually assigned by the parent process
Broker* g_broker = NULL;

/**
 * Signal handler used  by the child process forked to run the broker.
 */
static void sighandler(int signo) {
    if (g_broker != NULL)
        g_broker->stop();
}

class BrokerTests : public ::testing::Test {
 private:
    config_t* fe_config;
    config_t* be_config;
    config_t* pub_config;
    config_t* sub_config;
    void* pub_msgbus_ctx;
    void* sub_msgbus_ctx;
    recv_ctx_t* sub_ctx;
    publisher_ctx_t* pub_ctx;
    msg_envelope_t* msg;
    msg_envelope_t* received;
    pid_t broker_pid;

 protected:
    void SetUp() override {
        fe_config = NULL;
        be_config = NULL;
        pub_config = NULL;
        sub_config = NULL;
        pub_msgbus_ctx = NULL;
        sub_msgbus_ctx = NULL;
        sub_ctx = NULL;
        pub_ctx = NULL;
        msg = initialize_message();
        received = NULL;
        broker_pid = -1;
    }

    void TearDown() override {
        LOG_DEBUG_0("Cleaning up");
        // Clean up if an error happened
        if (received != NULL)
            msgbus_msg_envelope_destroy(received);
        if (msg != NULL)
            msgbus_msg_envelope_destroy(msg);
        if (pub_ctx != NULL)
            msgbus_publisher_destroy(pub_msgbus_ctx, pub_ctx);
        if (sub_ctx != NULL)
            msgbus_recv_ctx_destroy(sub_msgbus_ctx, sub_ctx);
        if (pub_msgbus_ctx != NULL)
            msgbus_destroy(pub_msgbus_ctx);
        else if (pub_config != NULL)
            config_destroy(pub_config);
        if (sub_msgbus_ctx != NULL)
            msgbus_destroy(sub_msgbus_ctx);
        else if (sub_config != NULL)
            config_destroy(sub_config);
        if (broker_pid > 0) {
            LOG_DEBUG("Killing broker child process: %d", broker_pid);
            kill(broker_pid, SIGTERM);

            LOG_DEBUG_0("Waiting fot the process to exit");
            int status = 0;
            waitpid(broker_pid, &status, 0);

            LOG_DEBUG_0("Broker stopped");
        }
    }

 public:
    void start_broker(const char* fe_conf_path, const char* be_conf_path,
                      int sched_policy, int sched_priority) {
        broker_pid = fork();
        if (broker_pid > 0) {
            // Wait for broker to start up
            sleep(3);
            return;
        }

        signal(SIGTERM, sighandler);

        try {
            // Else, child process
            config_t* fe_config = json_config_new(fe_conf_path);
            config_t* be_config = json_config_new(be_conf_path);
            LOG_DEBUG_0("Broker started");
            if (sched_policy != -1 || sched_priority != -1) {
                g_broker = new Broker(
                        fe_config, be_config, sched_policy, sched_priority);
            } else {
                g_broker = new Broker(fe_config, be_config);
            }
            g_broker->run_forever();
            delete g_broker;
            LOG_DEBUG_0("PROC BROKER EXITING");
            _exit(0);
        } catch (std::exception& ex) {
            LOG_ERROR("Error starting broker: %s", ex.what());
            _exit(-1);
        } catch (const char* err) {
            LOG_ERROR("Error starting broker: %s", err);
            _exit(-1);
        }
    }

    /**
     * Test harness to run the main body of a given test.
     */
    void run_test(
            const char* fe_conf_path, const char* be_conf_path,
            const char* pub_conf_path, const char* sub_conf_path,
            int sched_policy=-1, int sched_priority=-1) {
        LOG_DEBUG("RUNNING TEST: %s",
                ::testing::UnitTest::GetInstance()
                    ->current_test_info()
                    ->name());

        // Make sure that the broker configurations can be loaded succesfully
        // before forking the proces
        fe_config = json_config_new(fe_conf_path);
        ASSERT_NOT_NULL(fe_config);
        be_config = json_config_new(be_conf_path);
        ASSERT_NOT_NULL(be_config);

        config_destroy(fe_config);
        fe_config = NULL;
        config_destroy(be_config);
        be_config = NULL;

        // Start the broker process
        start_broker(fe_conf_path, be_conf_path, sched_policy, sched_priority);

        // Load configurations
        pub_config = json_config_new(pub_conf_path);
        ASSERT_NOT_NULL(pub_config);
        sub_config = json_config_new(sub_conf_path);
        ASSERT_NOT_NULL(sub_config);

        // Initialize message bus context
        pub_msgbus_ctx = msgbus_initialize(pub_config);
        ASSERT_NOT_NULL(pub_msgbus_ctx);
        sub_msgbus_ctx = msgbus_initialize(sub_config);
        ASSERT_NOT_NULL(sub_msgbus_ctx);

        // Initialize the publisher
        pub_ctx = NULL;
        msgbus_ret_t ret = msgbus_publisher_new(
                pub_msgbus_ctx, PUB_SUB_TOPIC, &pub_ctx);
        ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to create publisher";

        // Allow subscriber time to initialize and connect
        sleep(1);

        // Creating subscriber
        sub_ctx = NULL;
        ret = msgbus_subscriber_new(
                sub_msgbus_ctx, PUB_SUB_TOPIC, NULL, &sub_ctx);
        ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to create subscriber";

        // Allow subscriber time to initialize and connect
        sleep(1);

        ret = msgbus_publisher_publish(pub_msgbus_ctx, pub_ctx, msg);
        ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to publish message";

        // Allow time for publication to be received
        ret = msgbus_recv_timedwait(
                sub_msgbus_ctx, sub_ctx, 10 * 1000, &received);
        ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to recv message";
    }
};

TEST_F(BrokerTests, frontend_tcp_backend_tcp_no_security) {
    run_test("./configs/frontend_tcp_no_security.json",
             "./configs/backend_tcp_no_security.json",
             "./configs/msgbus_tcp_publisher_no_security.json",
             "./configs/msgbus_tcp_subscriber_no_security.json");
}

TEST_F(BrokerTests, frontend_tcp_backend_tcp_security_no_auth) {
    run_test("./configs/frontend_tcp_security_no_auth.json",
             "./configs/backend_tcp_security_no_auth.json",
             "./configs/msgbus_tcp_publisher_security.json",
             "./configs/msgbus_tcp_subscriber_security.json");
}

TEST_F(BrokerTests, frontend_tcp_backend_tcp_security_auth) {
    run_test("./configs/frontend_tcp_security_auth.json",
             "./configs/backend_tcp_security_auth.json",
             "./configs/msgbus_tcp_publisher_security.json",
             "./configs/msgbus_tcp_subscriber_security.json");
}

TEST_F(BrokerTests, frontend_ipc_backend_ipc) {
    run_test("./configs/frontend_ipc.json",
             "./configs/backend_ipc.json",
             "./configs/msgbus_ipc_publisher.json",
             "./configs/msgbus_ipc_subscriber.json");
}

TEST_F(BrokerTests, frontend_tcp_backend_ipc_no_security) {
    run_test("./configs/frontend_tcp_no_security.json",
             "./configs/backend_ipc.json",
             "./configs/msgbus_tcp_publisher_no_security.json",
             "./configs/msgbus_ipc_subscriber.json");
}

TEST_F(BrokerTests, frontend_tcp_backend_ipc_security_with_auth) {
    run_test("./configs/frontend_tcp_security_auth.json",
             "./configs/backend_ipc.json",
             "./configs/msgbus_tcp_publisher_security.json",
             "./configs/msgbus_ipc_subscriber.json");
}

TEST_F(BrokerTests, frontend_ipc_backend_tcp_no_security) {
    run_test("./configs/frontend_ipc.json",
             "./configs/backend_tcp_no_security.json",
             "./configs/msgbus_ipc_publisher.json",
             "./configs/msgbus_tcp_subscriber_no_security.json");
}

TEST_F(BrokerTests, frontend_ipc_backend_tcp_security_with_auth) {
    run_test("./configs/frontend_ipc.json",
             "./configs/backend_tcp_security_auth.json",
             "./configs/msgbus_ipc_publisher.json",
             "./configs/msgbus_tcp_subscriber_security.json");
}

TEST_F(BrokerTests, sched_batch_no_priority) {
    run_test("./configs/frontend_tcp_no_security.json",
             "./configs/backend_tcp_no_security.json",
             "./configs/msgbus_tcp_publisher_no_security.json",
             "./configs/msgbus_tcp_subscriber_no_security.json",
             SCHED_BATCH);
}

TEST_F(BrokerTests, sched_batch_with_priority) {
    // NOTE: This test should have a warning log statement saying that the
    // priority is being ignored, because SCHED_BATCH has no concept of
    // prioritization
    run_test("./configs/frontend_tcp_no_security.json",
             "./configs/backend_tcp_no_security.json",
             "./configs/msgbus_tcp_publisher_no_security.json",
             "./configs/msgbus_tcp_subscriber_no_security.json",
             SCHED_BATCH, 50);
}

TEST_F(BrokerTests, sched_fifo_no_priority) {
    // NOTE: This test should have a warning log statement saying that since
    // the priority is not provided it is defaulting to the lowest priority,
    // which is 1.
    run_test("./configs/frontend_tcp_no_security.json",
             "./configs/backend_tcp_no_security.json",
             "./configs/msgbus_tcp_publisher_no_security.json",
             "./configs/msgbus_tcp_subscriber_no_security.json",
             SCHED_FIFO);
}

TEST_F(BrokerTests, sched_fifo_with_priority) {
    // NOTE: This test should have a warning log statement saying that since
    // the priority is not provided it is defaulting to the lowest priority,
    // which is 1.
    run_test("./configs/frontend_tcp_no_security.json",
             "./configs/backend_tcp_no_security.json",
             "./configs/msgbus_tcp_publisher_no_security.json",
             "./configs/msgbus_tcp_subscriber_no_security.json",
             SCHED_FIFO, 50);
}

/**
 * Helper to initailize the message to be published
 */
static msg_envelope_t* initialize_message() {
    // Creating message to be published
    msg_envelope_elem_body_t* integer = msgbus_msg_envelope_new_integer(42);
    msg_envelope_elem_body_t* fp = msgbus_msg_envelope_new_floating(55.5);
    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_JSON);
    msgbus_msg_envelope_put(msg, "hello", integer);
    msgbus_msg_envelope_put(msg, "world", fp);
    return msg;
}

}  // namespace zmqbroker
}  // namespace eii

/**
 * Overridden GTest main method
 */
GTEST_API_ int main(int argc, char** argv) {
    // Parse out gTest command line parameters
    ::testing::InitGoogleTest(&argc, argv);

    // Check if log level provided
    if (argc == 3) {
        if (strcmp(argv[1], "--log-level") == 0) {
            // LOG_INFO_0("Running msgbus tests over TCP");
            char* log_level = argv[2];

            if (strcmp(log_level, "INFO") == 0) {
                set_log_level(LOG_LVL_INFO);
            } else if (strcmp(log_level, "DEBUG") == 0) {
                set_log_level(LOG_LVL_DEBUG);
            } else if (strcmp(log_level, "ERROR") == 0) {
                set_log_level(LOG_LVL_ERROR);
            } else if (strcmp(log_level, "WARN") == 0) {
                set_log_level(LOG_LVL_WARN);
            } else {
                LOG_ERROR("Unknown log level: %s", log_level);
                return -1;
            }
        } else {
            LOG_ERROR("Unknown parameter: %s", argv[1]);
            return -1;
        }
    } else if (argc == 2) {
        LOG_ERROR_0("Incorrect number of arguments");
        return -1;
    }

    // Run the tests
    return RUN_ALL_TESTS();
}
