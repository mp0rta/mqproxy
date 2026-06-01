cmake_minimum_required(VERSION 3.10)
project(mqproxy VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
include(cmake/BuildSetup.cmake)

add_library(mqproxy STATIC
    src/util/mq_log.c
    src/util/mq_buf.c
    src/wire/mq_varint.c
    src/wire/mq_wire.c
    src/proxy/mq_relay.c
    src/ingress/mq_socks5.c
    src/ingress/mq_http_connect.c
    src/transport/mq_engine.c
    src/transport/mq_path.c
    src/transport/mq_conn.c
    src/transport/mq_stream.c)
target_include_directories(mqproxy PUBLIC src ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})

enable_testing()
add_executable(test_smoke tests/test_smoke.c)
target_include_directories(test_smoke PRIVATE tests)
add_test(NAME test_smoke COMMAND test_smoke)

add_executable(test_varint tests/test_varint.c)
target_link_libraries(test_varint mqproxy)
target_include_directories(test_varint PRIVATE tests)
add_test(NAME test_varint COMMAND test_varint)

add_executable(test_wire tests/test_wire.c)
target_link_libraries(test_wire mqproxy)
target_include_directories(test_wire PRIVATE tests)
add_test(NAME test_wire COMMAND test_wire)

add_executable(test_buf tests/test_buf.c)
target_link_libraries(test_buf mqproxy)
target_include_directories(test_buf PRIVATE tests)
add_test(NAME test_buf COMMAND test_buf)

add_executable(test_relay tests/test_relay.c)
target_link_libraries(test_relay mqproxy)
target_include_directories(test_relay PRIVATE tests)
add_test(NAME test_relay COMMAND test_relay)

add_executable(test_socks5 tests/test_socks5.c)
target_link_libraries(test_socks5 mqproxy)
target_include_directories(test_socks5 PRIVATE tests)
add_test(NAME test_socks5 COMMAND test_socks5)

add_executable(test_http_connect tests/test_http_connect.c)
target_link_libraries(test_http_connect mqproxy)
target_include_directories(test_http_connect PRIVATE tests)
add_test(NAME test_http_connect COMMAND test_http_connect)

# ---- Integration tests (require xquic + libevent) ----
if(XQUIC_BUILD_DIR AND EVENT_CORE_LIB)
    add_executable(test_engine_boot tests/integration/test_engine_boot.c)
    target_link_libraries(test_engine_boot
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m)
    target_include_directories(test_engine_boot PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    # libxquic.so is loaded at runtime from the xquic build dir; embed an
    # rpath so ctest runs without LD_LIBRARY_PATH.
    set_target_properties(test_engine_boot PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_engine_boot COMMAND test_engine_boot)

    add_executable(test_path_bind tests/integration/test_path_bind.c)
    target_link_libraries(test_path_bind
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m)
    target_include_directories(test_path_bind PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    set_target_properties(test_path_bind PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_path_bind COMMAND test_path_bind)

    # Self-signed cert/key for the loopback handshake test. Committed under
    # tests/certs (test-only); regenerated at configure time if missing.
    set(MQ_CERT_DIR "${CMAKE_SOURCE_DIR}/tests/certs")
    set(MQ_CERT_FILE "${MQ_CERT_DIR}/test.crt")
    set(MQ_KEY_FILE "${MQ_CERT_DIR}/test.key")
    if(NOT EXISTS "${MQ_CERT_FILE}" OR NOT EXISTS "${MQ_KEY_FILE}")
        find_program(OPENSSL_BIN openssl REQUIRED)
        file(MAKE_DIRECTORY "${MQ_CERT_DIR}")
        message(STATUS "Generating self-signed test cert in ${MQ_CERT_DIR}")
        execute_process(
            COMMAND ${OPENSSL_BIN} req -x509 -newkey rsa:2048 -nodes
                    -keyout "${MQ_KEY_FILE}" -out "${MQ_CERT_FILE}"
                    -days 3650 -subj "/CN=mqproxy-test"
            RESULT_VARIABLE _cert_rc
            OUTPUT_QUIET ERROR_QUIET)
        if(NOT _cert_rc EQUAL 0)
            message(FATAL_ERROR "openssl failed to generate test cert")
        endif()
    endif()

    add_executable(test_conn_handshake tests/integration/test_conn_handshake.c)
    target_link_libraries(test_conn_handshake
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m)
    target_include_directories(test_conn_handshake PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_conn_handshake PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_conn_handshake PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_conn_handshake COMMAND test_conn_handshake)
endif()
