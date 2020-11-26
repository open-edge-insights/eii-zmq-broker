# Copyright (c) 2020 Intel Corporation.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM,OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

cmake_minimum_required(VERSION 3.11)
project(eis-zmq-broker VERSION 2.4.0 LANGUAGES C CXX)

# Define CMake options
option(WITH_TESTS    "Compile with unit tests" OFF)

# Globals
set(EIS_COMMON_CMAKE "${CMAKE_CURRENT_SOURCE_DIR}/../common/cmake")
set(CMAKE_MODULE_PATH "${EIS_COMMON_CMAKE}")

# Set C++ version
set(CMAKE_CXX_STANDARD 14)

# Set C standard to C11
set(CMAKE_C_STANDARD 11)

# Set CFLAGS for C/C++
set(CMAKE_C_FLAGS "-fPIE -fPIC -O2 -Wall -fstack-protector-strong -D_FORTIFY_SOURCE=2")
set(CMAKE_CXX_FLAGS "-fPIE -fPIC -O2 -Wall -fstack-protector-strong -D_FORTIFY_SOURCE=2")

# Set LDFLAGS
set(CMAKE_SHARED_LINKER_FLAGS "-z noexecstack -z relro -z now")

# Find packages
find_package(IntelSafeString REQUIRED)
find_package(EISUtils REQUIRED)
find_package(ZMQ REQUIRED)
find_package(EISConfigMgr REQUIRED)

# Export compile commands
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json")
    EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
        ${CMAKE_CURRENT_SOURCE_DIR}/compile_commands.json
    )
endif()

# Include header directories
include_directories(
include/
${IntelSafeString_INCLUDE}
${EISConfigMgr_INCLUDE}
${EISUtils_INCLUDE}
${ZMQ_INCLUDE_DIRS})

# Copy over example configuration files
file(GLOB CONFIGS "examples/*.json")
foreach(CONFIG ${CONFIGS})
    file(COPY "${CONFIG}" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/examples")
endforeach()

# List out all C sources and set language property to C
file(GLOB C_SOURCES "src/*.c")
set_source_files_properties(${C_SOURCES} PROPERTIES LANGUAGE C)

# List out all C++ sources and set language property to C++
file(GLOB CXX_SOURCES "src/*.cpp")
set_source_files_properties(${CXX_SOURCES} PROPERTIES LANGUAGE CXX)

# Add EIS ZeroMQ Broker target
add_executable(eis-zmq-broker "${CXX_SOURCES}" "${C_SOURCES}")
target_link_libraries(eis-zmq-broker
    pthread
    ${EISConfigMgr_LIBRARIES}
    ${IntelSafeString_LIBRARIES}
    ${EISUtils_LIBRARIES}
    ${ZMQ_LIBRARIES})

if(WITH_TESTS)
    add_subdirectory(tests/)
endif()
