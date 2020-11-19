# Copyright (c) 2020 Intel Corporation.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Dockerfile for cpp_publisher
ARG EIS_VERSION
ARG DOCKER_REGISTRY
ARG CMAKE_BUILD_TYPE
ARG RUN_TESTS

FROM ${DOCKER_REGISTRY}ia_eisbase:$EIS_VERSION as eisbase
LABEL description="ia_eis_zmq_broker image"

ARG EIS_UID
ARG EIS_USER_NAME
RUN useradd -r -u ${EIS_UID} -G video ${EIS_USER_NAME}

FROM ${DOCKER_REGISTRY}ia_common:$EIS_VERSION as common
FROM eisbase
WORKDIR ${PY_WORK_DIR}

ENV LD_LIBRARY_PATH ${LD_LIBRARY_PATH}:/usr/local/lib

COPY --from=common /usr/local/include /usr/local/include
COPY --from=common /usr/local/lib /usr/local/lib
COPY --from=common ${GO_WORK_DIR}/common/cmake ./common/cmake
COPY --from=common ${GO_WORK_DIR}/common/libs ./common/libs
COPY --from=common ${GO_WORK_DIR}/common/util ${GO_WORK_DIR}/common/util
COPY --from=common /usr/local/lib/python3.6/dist-packages/ /usr/local/lib/python3.6/dist-packages

COPY . EISZmqBroker/

# Build the EIS ZeroMQ broker
RUN cd ./EISZmqBroker/ && \
    rm -rf build/ && \
    mkdir build/ && \
    cd build/ && \
    cmake -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} .. && \
    make

HEALTHCHECK NONE

ENTRYPOINT ["EISZmqBroker/build/eis-zmq-broker"]
