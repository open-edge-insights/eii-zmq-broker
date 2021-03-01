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
configure_file(
    "${EII_COMMON_CMAKE}/GoogleTestCMakeLists.txt.in"
    "${CMAKE_CURRENT_BINARY_DIR}/googletest-download/CMakeLists.txt")
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
                RESULT_VARIABLE result
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download)
if(result)
    message(FATAL_ERROR "CMake step for googletest failed: ${result}")
endif()

execute_process(COMMAND ${CMAKE_COMMAND} --build .
                RESULT_VARIABLE result
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download)
if(result)
    message(FATAL_ERROR "Build step for googletest failed: ${result}")
endif()

# Prevent overriding the parent project's compiler/linker
# settings on Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# Add googletest directly to our build. This defines
# the gtest and gtest_main targets.
add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
                 ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
                 EXCLUDE_FROM_ALL)

# The gtest/gtest_main targets carry header search path
# dependencies automatically when using CMake 2.8.11 or
# later. Otherwise we have to add them here ourselves.
if (CMAKE_VERSION VERSION_LESS 2.8.11)
    include_directories("${gtest_SOURCE_DIR}/include")
endif()

# Need the EII Message Bus for the broker tests
find_package(EIIMsgEnv REQUIRED)
find_package(EIIMessageBus REQUIRED)

# Remove main.cpp from the sources list which will get linked to the broker
# tests. This is so that there are not two main entry points to the unit test
# binary.
list(REMOVE_ITEM CXX_SOURCES "${PROJECT_SOURCE_DIR}/src/main.cpp")

# Now simply link against gtest or gtest_main as needed. Eg
add_executable(broker-tests "broker_tests.cpp" ${CXX_SOURCES} ${C_SOURCES})
target_link_libraries(broker-tests gtest_main
    ${EIIConfigMgrNew_LIBRARIES}
    ${EIIUtils_LIBRARIES}
    ${EIIMsgEnv_LIBRARIES}
    ${EIIMessageBus_LIBRARIES}
    ${EIIUtils_LIBRARIES}
    ${ZMQ_LIBRARIES}
    ${IntelSafeString_LIBRARIES})
target_include_directories(broker-tests PRIVATE
    ${EIIMsgEnv_INCLUDE}
    ${EIIMessageBus_INCLUDE})
add_test(NAME broker-tests COMMAND broker-tests)

# Make IPC socket directory
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/.socks")

# Copy JSON configuration for broker-tests
file(GLOB CONFIGS "configs/*.json")
foreach(CONFIG ${CONFIGS})
    file(COPY "${CONFIG}" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/configs")
endforeach()
