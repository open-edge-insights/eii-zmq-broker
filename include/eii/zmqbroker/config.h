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
 * @brief Configuration utilities
 */

#ifndef ZMQ_BROKER_INCLUDE_ZMQBROKER_CONFIG_H_
#define ZMQ_BROKER_INCLUDE_ZMQBROKER_CONFIG_H_

#include <eii/config_manager/app_cfg.hpp>

namespace eii {
namespace zmqbroker {

/**
 * Wrap a @c eii::config_manager::AppCfg object in a @c config_t structure
 * for the @c Broker class to digest the configuration.
 *
 * @param cfg - @c eii::config_manager::AppCfg object to wrap
 * @return config_t*
 */
config_t* wrap_appcfg(config_manager::AppCfg* cfg);

}  // namespace zmqbroker
}  // namespace eii

#endif  // ZMQ_BROKER_INCLUDE_ZMQBROKER_CONFIG_H_
