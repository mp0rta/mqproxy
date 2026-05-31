cmake_minimum_required(VERSION 3.10)
project(mqproxy VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
include(cmake/BuildSetup.cmake)

add_library(mqproxy STATIC
    src/util/mq_log.c)
target_include_directories(mqproxy PUBLIC src ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})

enable_testing()
add_executable(test_smoke tests/test_smoke.c)
target_include_directories(test_smoke PRIVATE tests)
add_test(NAME test_smoke COMMAND test_smoke)
