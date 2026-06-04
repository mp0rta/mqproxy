cmake_minimum_required(VERSION 3.10)
project(mqproxy VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
include(cmake/BuildSetup.cmake)
find_package(CURL REQUIRED)

add_library(mqproxy STATIC
    src/util/mq_log.c
    src/util/mq_buf.c
    src/wire/mq_varint.c
    src/wire/mq_wire.c
    src/proxy/mq_relay.c
    src/proxy/mq_flow.c
    src/proxy/mq_framebuf.c
    src/proxy/mq_client.c
    src/proxy/mq_server.c
    src/ingress/mq_socks5.c
    src/ingress/mq_http_connect.c
    src/ingress/mq_listener.c
    src/gateway/mq_http1.c
    src/gateway/mq_gw_headers.c
    src/gateway/mq_fetch_listener.c
    src/gateway/mq_gw_client.c
    src/gateway/mq_gw_server.c
    src/gateway/mq_origin_curl.c
    src/transport/mq_conn.c
    src/transport/mq_h3.c
    src/transport/mq_stream.c
    src/transport/mq_transport.c
    src/runtime/mq_runtime_libevent.c)
target_link_libraries(mqproxy PUBLIC CURL::libcurl)
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

add_executable(test_http1 tests/test_http1.c)
target_link_libraries(test_http1 mqproxy)
target_include_directories(test_http1 PRIVATE tests)
add_test(NAME test_http1 COMMAND test_http1)

add_executable(test_gw_headers tests/test_gw_headers.c)
target_link_libraries(test_gw_headers mqproxy)
target_include_directories(test_gw_headers PRIVATE tests)
add_test(NAME test_gw_headers COMMAND test_gw_headers)

# ---- Integration tests (require xquic + libevent) ----
if(XQUIC_BUILD_DIR AND EVENT_CORE_LIB)
    add_executable(test_engine_boot tests/integration/test_engine_boot.c)
    target_link_libraries(test_engine_boot
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
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
        pthread dl m stdc++)
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

    # Origin TLS cert/key for the gateway e2e (e2e_gateway.sh). UNLIKE test.crt
    # this cert carries subjectAltName=IP:127.0.0.1 so the gateway server can
    # verify the origin's hostname (we NEVER disable verification — the server
    # gets --origin-ca pointed at this cert). Test-only; regenerated if missing.
    set(MQ_ORIGIN_CERT_FILE "${MQ_CERT_DIR}/origin.crt")
    set(MQ_ORIGIN_KEY_FILE "${MQ_CERT_DIR}/origin.key")
    if(NOT EXISTS "${MQ_ORIGIN_CERT_FILE}" OR NOT EXISTS "${MQ_ORIGIN_KEY_FILE}")
        find_program(OPENSSL_BIN openssl REQUIRED)
        file(MAKE_DIRECTORY "${MQ_CERT_DIR}")
        message(STATUS "Generating self-signed origin cert (SAN=IP:127.0.0.1) in ${MQ_CERT_DIR}")
        execute_process(
            COMMAND ${OPENSSL_BIN} req -x509 -newkey rsa:2048 -nodes
                    -keyout "${MQ_ORIGIN_KEY_FILE}" -out "${MQ_ORIGIN_CERT_FILE}"
                    -days 3650 -subj "/CN=mqproxy-origin"
                    -addext "subjectAltName=IP:127.0.0.1"
            RESULT_VARIABLE _origin_cert_rc
            OUTPUT_QUIET ERROR_QUIET)
        if(NOT _origin_cert_rc EQUAL 0)
            message(FATAL_ERROR "openssl failed to generate origin test cert")
        endif()
    endif()

    add_executable(test_conn_handshake tests/integration/test_conn_handshake.c)
    target_link_libraries(test_conn_handshake
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_conn_handshake PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_conn_handshake PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_conn_handshake PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_conn_handshake COMMAND test_conn_handshake)

    add_executable(test_client_server tests/integration/test_client_server.c)
    target_link_libraries(test_client_server
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_client_server PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_client_server PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_client_server PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_client_server COMMAND test_client_server)

    add_executable(test_socks5_listener tests/integration/test_socks5_listener.c)
    target_link_libraries(test_socks5_listener
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_socks5_listener PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    set_target_properties(test_socks5_listener PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_socks5_listener COMMAND test_socks5_listener)

    # Fetch-API listener (Task 2.2) + gateway client fetch→H3 bridge (Task 3.2).
    # The listener cases drive the loopback HTTP/1.1 accept loop with fake gateway
    # callbacks over real sockets; the gateway-client cases stand up real
    # client+server transports + runtimes + mq_h3 over loopback UDP, so this test
    # now needs the cert/key defines (mirrors test_e2e_single_path).
    add_executable(test_gw_client tests/integration/test_gw_client.c)
    target_link_libraries(test_gw_client
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_gw_client PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_gw_client PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_gw_client PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_gw_client COMMAND test_gw_client)

    # mq_origin_curl (Task 4.2): the libcurl-multi origin client on libevent.
    # Drives the mq_origin_* API against an in-process evhttp origin over plain
    # loopback HTTP/1.1. evhttp lives in libevent_extra (EVENT_EXTRA_LIB); curl
    # propagates from mqproxy's PUBLIC CURL::libcurl link. Task 4.3 extends this
    # file with the gateway-server replay cases.
    add_executable(test_gw_server tests/integration/test_gw_server.c)
    target_link_libraries(test_gw_server
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_gw_server PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    # Task 4.3 extends this test with gw_server cases that stand up a real H3
    # client+server over loopback UDP, so it needs the cert/key defines.
    target_compile_definitions(test_gw_server PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_gw_server PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_gw_server COMMAND test_gw_server)

    add_executable(test_e2e_single_path tests/integration/test_e2e_single_path.c)
    target_link_libraries(test_e2e_single_path
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_e2e_single_path PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_e2e_single_path PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_e2e_single_path PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_e2e_single_path COMMAND test_e2e_single_path)

    add_executable(test_transport_fabric tests/integration/test_transport_fabric.c)
    target_link_libraries(test_transport_fabric
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_transport_fabric PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_transport_fabric PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_transport_fabric PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_transport_fabric COMMAND test_transport_fabric)

    add_executable(test_h3_fabric tests/integration/test_h3_fabric.c)
    target_link_libraries(test_h3_fabric
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_h3_fabric PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_h3_fabric PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_h3_fabric PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_h3_fabric COMMAND test_h3_fabric)

    add_executable(test_two_paths tests/integration/test_two_paths.c)
    target_link_libraries(test_two_paths
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_two_paths PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_two_paths PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_two_paths PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_two_paths COMMAND test_two_paths)

    add_executable(test_qlog_blocked tests/integration/test_qlog_blocked.c)
    target_link_libraries(test_qlog_blocked
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_qlog_blocked PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_qlog_blocked PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_qlog_blocked PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_qlog_blocked COMMAND test_qlog_blocked)

    # ---- mqproxy CLI (client/server binaries) ----
    # The static library target is also named `mqproxy`; give the executable a
    # distinct target name but emit it as the `mqproxy` binary.
    add_executable(mqproxy_cli cli/main.c)
    set_target_properties(mqproxy_cli PROPERTIES OUTPUT_NAME mqproxy)
    target_link_libraries(mqproxy_cli
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(mqproxy_cli PRIVATE src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    # Default cert/key for `server` come from the bundled test cert (so the
    # binary is runnable out of the box); real deployments pass --cert/--key.
    target_compile_definitions(mqproxy_cli PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(mqproxy_cli PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")

    # CLI help / smoke test (shell): asserts --help works and unknown
    # subcommands fail. Passes the binary path via $<TARGET_FILE:mqproxy>.
    add_test(NAME test_cli_help
        COMMAND ${CMAKE_COMMAND} -E env
            sh ${CMAKE_SOURCE_DIR}/tests/test_cli_help.sh $<TARGET_FILE:mqproxy_cli>)

    # ---- 1-B multipath aggregation benchmark (design §9.2) ----
    # Self-contained bash benchmark the USER runs with sudo: it shapes two
    # loopback paths with tc/netem, runs a single-path vs two-path bulk transfer
    # through the proxy, and asserts >=1.5x aggregation + zero blocked frames in
    # the client qlog. It REQUIRES NET_ADMIN (tc); without it the script exits 77
    # so ctest marks it SKIPPED rather than FAILED. The mqproxy binary path and
    # the test cert/key are passed via env so the script needs no build knowledge.
    add_test(NAME e2e_multipath
        COMMAND ${CMAKE_COMMAND} -E env
            MQPROXY_BIN=$<TARGET_FILE:mqproxy_cli>
            MQPROXY_CERT=${MQ_CERT_FILE}
            MQPROXY_KEY=${MQ_KEY_FILE}
            bash ${CMAKE_SOURCE_DIR}/tests/integration/e2e_multipath.sh)
    set_tests_properties(e2e_multipath PROPERTIES SKIP_RETURN_CODE 77)

    # ---- Phase 2 Task 5.1: full-chain HTTP-gateway e2e ----
    # Drives the whole fetch path against a real python3 TLS origin: 8MB
    # download/upload byte-exact, the 4xx/502/504 error surface (with x-mq-error
    # / x-mq-origin-protocol assertions), and a NET_ADMIN-gated 2-path
    # aggregation smoke. Cases 1-7 run anywhere; case 8 needs tc on lo and is
    # skipped (a note) without it. The WHOLE script exits 77 (SKIP) ONLY when the
    # python3 TLS origin can't start. The mqproxy binary, the tunnel cert/key,
    # and the SAN'd origin cert/key are passed via env.
    add_test(NAME e2e_gateway
        COMMAND ${CMAKE_COMMAND} -E env
            MQPROXY_BIN=$<TARGET_FILE:mqproxy_cli>
            MQPROXY_CERT=${MQ_CERT_FILE}
            MQPROXY_KEY=${MQ_KEY_FILE}
            MQPROXY_ORIGIN_CERT=${MQ_ORIGIN_CERT_FILE}
            MQPROXY_ORIGIN_KEY=${MQ_ORIGIN_KEY_FILE}
            bash ${CMAKE_SOURCE_DIR}/tests/integration/e2e_gateway.sh)
    set_tests_properties(e2e_gateway PROPERTIES SKIP_RETURN_CODE 77)
endif()
