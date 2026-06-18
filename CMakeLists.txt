cmake_minimum_required(VERSION 3.10)
project(mqproxy VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Warning gate for first-party code. The tree compiles clean under these; not
# -Werror by default so a newer compiler's novel warning never blocks a distro
# build (CI can add -Werror). xquic/BoringSSL are prebuilt + linked, not compiled
# here, so these flags only touch mqproxy's own sources.
add_compile_options(-Wall -Wextra)

include(cmake/BuildSetup.cmake)
include(GNUInstallDirs)
if(MQPROXY_H3_CURL)
    add_library(CURL::libcurl SHARED IMPORTED)
    set_target_properties(CURL::libcurl PROPERTIES
        IMPORTED_LOCATION "${MQPROXY_H3_CURL}/lib/libcurl.so"
        INTERFACE_INCLUDE_DIRECTORIES "${MQPROXY_H3_CURL}/include")
    # RPATH: do NOT use a global set(CMAKE_BUILD_RPATH ...) here — this tree sets a
    # bare per-target BUILD_RPATH "${XQUIC_BUILD_DIR}" on all 20 executables
    # (e.g. :355 test_gw_server, :473 mqproxy_cli), and set_target_properties REPLACES
    # (not appends), so a global value would be dropped. USE_LINK_PATH instead ADDS the
    # imported .so's directory to each target's RPATH, combining with the per-target value.
    set(CMAKE_BUILD_RPATH_USE_LINK_PATH ON)
else()
    find_package(CURL REQUIRED)
endif()

add_library(mqproxy STATIC
    src/util/mq_log.c
    src/util/mq_buf.c
    src/util/mq_backoff.c
    src/config/mq_config.c
    src/wire/mq_varint.c
    src/wire/mq_wire.c
    src/wire/mq_udp_msg.c
    src/proxy/mq_relay.c
    src/proxy/mq_flow.c
    src/proxy/mq_framebuf.c
    src/proxy/mq_defrag.c
    src/proxy/mq_client.c
    src/proxy/mq_server.c
    src/proxy/mq_udp_session.c
    src/ingress/mq_socks5.c
    src/ingress/mq_http_connect.c
    src/ingress/mq_origdst.c
    src/ingress/mq_clienthello.c
    src/ingress/mq_tproxy.c
    src/ingress/mq_tproxy_setup.c
    src/ingress/mq_listener.c
    src/ingress/mq_udp_assoc.c
    src/gateway/mq_http1.c
    src/gateway/mq_gw_headers.c
    src/gateway/mq_fetch_listener.c
    src/gateway/mq_gw_client.c
    src/gateway/mq_gw_fetch_adapter.c
    src/gateway/mq_gw_server.c
    src/gateway/mq_gw_metrics.c
    src/gateway/mq_gw_cache.c
    src/gateway/mq_origin_curl.c
    src/transport/mq_conn.c
    src/transport/mq_h3.c
    src/transport/mq_stream.c
    src/transport/mq_transport.c
    src/runtime/mq_runtime_libevent.c
    src/gateway/mq_gw_h2_adapter.c
    src/gateway/mq_gw_h2_submit_gwc.c
    src/mitm/mq_ignore_hosts.c)
target_include_directories(mqproxy PUBLIC ${NGHTTP2_INCLUDE_DIRS})
target_link_libraries(mqproxy PUBLIC CURL::libcurl)
target_include_directories(mqproxy PUBLIC src ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})

# Fail-closed MITM gate (Slice 3 Task 3, codex H7): mq_mitm_core.c #includes
# BoringSSL headers (openssl/bytestring.h etc.) that exist only with the static
# archives. Compile it — and its BoringSSL include dir — into the library ONLY
# when the archives are present (MQPROXY_MITM). A no-archive build therefore
# pulls NO MITM source and the whole tree (library + mqproxy_cli) builds/links
# cleanly; `--mitm` then errors at startup via the MQ_MITM_AVAILABLE=0 guard.
if(MQPROXY_MITM)
    # mq_mitm_core.c #includes BoringSSL headers; mq_mitm_conn.c (live orchestrator,
    # Task 10) references mq_mitm_core types. Both compile into the lib only under
    # MQPROXY_MITM. The CLI links the lib, so adding mq_mitm_conn here (not to
    # mqproxy_cli) also satisfies the test_mitm_conn target, which links `mqproxy`.
    target_sources(mqproxy PRIVATE src/mitm/mq_mitm_core.c src/mitm/mq_mitm_conn.c)
    target_include_directories(mqproxy PUBLIC ${MQPROXY_BORINGSSL_INCLUDE_DIR})
endif()

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

add_executable(test_udp_msg tests/test_udp_msg.c)
target_link_libraries(test_udp_msg mqproxy)
target_include_directories(test_udp_msg PRIVATE tests)
add_test(NAME test_udp_msg COMMAND test_udp_msg)

add_executable(test_buf tests/test_buf.c)
target_link_libraries(test_buf mqproxy)
target_include_directories(test_buf PRIVATE tests)
add_test(NAME test_buf COMMAND test_buf)

add_executable(test_config tests/test_config.c)
target_link_libraries(test_config mqproxy)
target_include_directories(test_config PRIVATE tests)
add_test(NAME test_config COMMAND test_config)

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

add_executable(test_gw_cache tests/test_gw_cache.c)
target_link_libraries(test_gw_cache mqproxy)
target_include_directories(test_gw_cache PRIVATE tests src)
add_test(NAME test_gw_cache COMMAND test_gw_cache)

add_executable(test_defrag tests/test_defrag.c)
target_link_libraries(test_defrag mqproxy)
target_include_directories(test_defrag PRIVATE tests)
add_test(NAME test_defrag COMMAND test_defrag)

add_executable(test_backoff tests/test_backoff.c)
target_link_libraries(test_backoff mqproxy)
target_include_directories(test_backoff PRIVATE tests)
add_test(NAME test_backoff COMMAND test_backoff)

add_executable(test_gw_req_format tests/test_gw_req_format.c src/gateway/mq_gw_metrics.c)
target_include_directories(test_gw_req_format PRIVATE tests src)  # tests → mqtest.h, src → gateway/mq_gw_metrics.h
add_test(NAME test_gw_req_format COMMAND test_gw_req_format)

add_executable(test_origdst tests/test_origdst.c)
target_link_libraries(test_origdst mqproxy)
target_include_directories(test_origdst PRIVATE tests)
add_test(NAME test_origdst COMMAND test_origdst)

add_executable(test_clienthello tests/test_clienthello.c)
target_link_libraries(test_clienthello mqproxy)
target_include_directories(test_clienthello PRIVATE tests src)
add_test(NAME test_clienthello COMMAND test_clienthello)

add_executable(test_ignore_hosts tests/test_ignore_hosts.c)
target_link_libraries(test_ignore_hosts mqproxy)
target_include_directories(test_ignore_hosts PRIVATE tests src)
add_test(NAME test_ignore_hosts COMMAND test_ignore_hosts)

# nghttp2 link probe (Slice 3 Task 4): permanent low-cost guard that the nghttp2
# dependency stays compiled + linked + runnable in BOTH build modes. Links the
# static archive under MQPROXY_STATIC_XQUIC (self-contained packaging binary),
# else the system shared lib — same selection the live H2 MITM adapter uses. No
# xquic/BoringSSL needed (nghttp2 is a leaf), so it lives in the unconditional
# section. Calls nghttp2_version() and prints the runtime version string.
add_executable(nghttp2_link_probe tests/nghttp2_link_probe.c)
target_include_directories(nghttp2_link_probe PRIVATE ${NGHTTP2_INCLUDE_DIRS})
if(MQPROXY_STATIC_XQUIC AND NGHTTP2_STATIC_LIB)
    # Exercise the exact static archive the packaging cli links. (When the .a is
    # absent the cli static branch already FATAL_ERRORs; the probe falls back to
    # the shared lib here only to stay buildable for non-cli static configs.)
    target_link_libraries(nghttp2_link_probe "${NGHTTP2_STATIC_LIB}")
else()
    target_link_libraries(nghttp2_link_probe ${NGHTTP2_LIBRARIES})
endif()
add_test(NAME nghttp2_link_probe COMMAND nghttp2_link_probe)

# nghttp2 H2 server adapter unit suite (Slice 3 Task 5). Pure H2 framing — drives
# a real nghttp2 CLIENT through an in-test memory pipe against the adapter SERVER
# session; no xquic/BoringSSL needed (the adapter .o is pulled out of the base
# mqproxy lib, which references only nghttp2). Lives in the unconditional section.
add_executable(test_gw_h2_adapter tests/test_gw_h2_adapter.c)
target_link_libraries(test_gw_h2_adapter mqproxy ${NGHTTP2_LIBRARIES})
target_include_directories(test_gw_h2_adapter PRIVATE tests src ${NGHTTP2_INCLUDE_DIRS})
add_test(NAME test_gw_h2_adapter COMMAND test_gw_h2_adapter)

# ---- Integration tests (require xquic + libevent) ----
if(XQUIC_BUILD_DIR AND EVENT_CORE_LIB)
    # ---- Phase 7 Slice 2: MITM crypto core unit suite ----
    # Needs the BoringSSL static archives libxquic was built against (SSL_*/X509_*).
    # The mq_boringssl INTERFACE target is defined in cmake/BuildSetup.cmake
    # (hoisted out of this test-only block so mqproxy_cli can also consume it).
    # GATE: MQPROXY_MITM, NOT MQ_HAVE_BORINGSSL_ARCHIVES. These targets reference
    # mq_mitm_core_* symbols, which are compiled into the mqproxy lib only under
    # MQPROXY_MITM (see ~line 69). Gating them on the raw-archive predicate while
    # the source compilation is gated on MQPROXY_MITM would let a hypothetical
    # MQPROXY_MITM=OFF + archives-present build still emit these targets and then
    # fail to LINK with undefined mq_mitm_core_* — a confusing failure far from the
    # cause. MQPROXY_MITM is an alias of MQ_HAVE_BORINGSSL_ARCHIVES today, so this
    # is behavior-preserving; it makes the documented decoupling actually safe.
    if(MQPROXY_MITM)
        add_executable(test_mitm_core tests/test_mitm_core.c)
        target_link_libraries(test_mitm_core mqproxy mq_boringssl)
        target_include_directories(test_mitm_core PRIVATE tests src)
        add_test(NAME test_mitm_core COMMAND test_mitm_core)

        # ---- Task 10: live MITM conn orchestrator decision-seam unit ----
        # Exercises the drain→decide routing (ignore-hosts hit→opaque vs miss→MITM)
        # via the socketless decision seam. Links mqproxy + mq_boringssl (touches
        # mq_mitm_core types via the orchestrator) + libevent (the orchestrator
        # creates events; the seam itself uses none).
        # NOTE: as of Task 11 mq_mitm_conn.c wires the live MITM path through the
        # production submit wrapper (mq_gw_h2_adapter → mq_gw_client_* → xquic), so
        # the orchestrator object now references nghttp2 + the full xquic/BoringSSL
        # stack even on the decision-seam path. These unit targets therefore link the
        # whole stack (xquic + nghttp2 + mq_boringssl + libevent) like the other
        # integration tests, plus the xquic runtime rpath.
        add_executable(test_mitm_conn tests/test_mitm_conn.c)
        target_link_libraries(test_mitm_conn mqproxy xquic mq_boringssl
            ${NGHTTP2_LIBRARIES} ${EVENT_CORE_LIB} ${EVENT_EXTRA_LIB}
            pthread dl m stdc++)
        target_include_directories(test_mitm_conn PRIVATE tests src
            ${NGHTTP2_INCLUDE_DIRS})
        set_target_properties(test_mitm_conn PROPERTIES BUILD_RPATH "${XQUIC_BUILD_DIR}")
        add_test(NAME test_mitm_conn COMMAND test_mitm_conn)

        # ---- Task 11: live MITM conn registry + ordered teardown + re-entrancy ----
        # Builds real nghttp2 adapters holding in-flight streams, registers them in
        # live MITM conns via the make_live_for_test seam, then mq_mitm_ctx_free —
        # asserting each in-flight stream's req_aborted fires exactly once and the
        # teardown is ASan/LSan-clean (no UAF/leak/double-free). Links the full stack
        # (the orchestrator references SSL_*/BIO_* + the gwc submit wrapper → xquic).
        add_executable(test_mitm_teardown tests/test_mitm_teardown.c)
        target_link_libraries(test_mitm_teardown mqproxy xquic mq_boringssl
            ${NGHTTP2_LIBRARIES} ${EVENT_CORE_LIB} ${EVENT_EXTRA_LIB}
            pthread dl m stdc++)
        target_include_directories(test_mitm_teardown PRIVATE tests src
            ${NGHTTP2_INCLUDE_DIRS})
        set_target_properties(test_mitm_teardown PROPERTIES
            BUILD_RPATH "${XQUIC_BUILD_DIR}")
        add_test(NAME test_mitm_teardown COMMAND test_mitm_teardown)

        # ---- Task 8: openssl s_client cross-implementation smoke ----
        # The single-shot helper terminates a real loopback TLS handshake via
        # mq_mitm_core; the shell driver runs `openssl s_client` against it and
        # asserts ALPN=h2 + chain-verify.
        add_executable(mitm_smoke_server tests/integration/mitm_smoke_server.c)
        target_link_libraries(mitm_smoke_server mqproxy mq_boringssl)
        target_include_directories(mitm_smoke_server PRIVATE src)
        # NOTE: add_test for e2e_mitm_smoke is registered below, after the MITM CA
        # fixture paths (MQ_MITM_CA_*) are defined — same pattern as the
        # test_mitm_core compile_definitions block.
    else()
        message(STATUS "BoringSSL archives absent — test_mitm_core not built "
                       "(run scripts/build-xquic.sh).")
    endif()

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

    add_executable(test_sched tests/test_sched.c)
    target_link_libraries(test_sched
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_sched PRIVATE tests src ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    set_target_properties(test_sched PROPERTIES BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_sched COMMAND test_sched)

    add_executable(test_metrics_format tests/test_metrics_format.c)
    target_link_libraries(test_metrics_format
        mqproxy xquic ${EVENT_CORE_LIB} ${EVENT_EXTRA_LIB} pthread dl m stdc++)
    target_include_directories(test_metrics_format PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    set_target_properties(test_metrics_format PROPERTIES BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_metrics_format COMMAND test_metrics_format)

    # Connection-count cap (--max-conns) counter API — pre-auth DoS. Pure counter
    # logic, no handshake.
    add_executable(test_max_conns tests/test_max_conns.c)
    target_link_libraries(test_max_conns
        mqproxy xquic ${EVENT_CORE_LIB} ${EVENT_EXTRA_LIB} pthread dl m stdc++)
    target_include_directories(test_max_conns PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    set_target_properties(test_max_conns PROPERTIES BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_max_conns COMMAND test_max_conns)

    # mq_h3_req_get_stats + mq_h3_req_stream_id NULL-guard unit tests.
    # Links mq_h3.o -> xqc_* so it lives in the xquic-gated block.
    add_executable(test_h3_req_stats tests/test_h3_req_stats.c)
    target_link_libraries(test_h3_req_stats
        mqproxy xquic ${EVENT_CORE_LIB} ${EVENT_EXTRA_LIB} pthread dl m stdc++)
    target_include_directories(test_h3_req_stats PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    set_target_properties(test_h3_req_stats PROPERTIES BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_h3_req_stats COMMAND test_h3_req_stats)

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
    # this cert carries subjectAltName=IP:127.0.0.1,DNS:localhost so the gateway
    # server can verify the origin's hostname (we NEVER disable verification — the
    # server gets --origin-ca pointed at this cert). The DNS:localhost SAN lets the
    # gated h3 sub-case target https://localhost (curl sends SNI for a hostname but
    # NOT for an IP literal, and xquic's demo_server REQUIRES SNI). Test-only;
    # regenerated if missing.
    set(MQ_ORIGIN_CERT_FILE "${MQ_CERT_DIR}/origin.crt")
    set(MQ_ORIGIN_KEY_FILE "${MQ_CERT_DIR}/origin.key")
    if(NOT EXISTS "${MQ_ORIGIN_CERT_FILE}" OR NOT EXISTS "${MQ_ORIGIN_KEY_FILE}")
        find_program(OPENSSL_BIN openssl REQUIRED)
        file(MAKE_DIRECTORY "${MQ_CERT_DIR}")
        message(STATUS "Generating self-signed origin cert (SAN=IP:127.0.0.1,DNS:localhost) in ${MQ_CERT_DIR}")
        execute_process(
            COMMAND ${OPENSSL_BIN} req -x509 -newkey rsa:2048 -nodes
                    -keyout "${MQ_ORIGIN_KEY_FILE}" -out "${MQ_ORIGIN_CERT_FILE}"
                    -days 3650 -subj "/CN=mqproxy-origin"
                    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
            RESULT_VARIABLE _origin_cert_rc
            OUTPUT_QUIET ERROR_QUIET)
        if(NOT _origin_cert_rc EQUAL 0)
            message(FATAL_ERROR "openssl failed to generate origin test cert")
        endif()
    endif()

    # MITM CA + negative fixtures (test-only; regenerated if missing).
    # NOTE (rev2/C1): do NOT reuse tests/certs/test.crt as the non-CA negative —
    # it is actually CA:TRUE. We mint a dedicated CA:FALSE leaf below.
    set(MQ_MITM_CA_CRT     "${MQ_CERT_DIR}/mitm-ca.crt")
    set(MQ_MITM_CA_KEY     "${MQ_CERT_DIR}/mitm-ca.key")
    set(MQ_MITM_CA_ENC_KEY "${MQ_CERT_DIR}/mitm-ca.enc.key") # encrypted (must be rejected)
    set(MQ_MITM_LEAF_CRT   "${MQ_CERT_DIR}/mitm-leaf.crt")   # CA:FALSE → non-CA negative
    set(MQ_MITM_LEAF_KEY   "${MQ_CERT_DIR}/mitm-leaf.key")   # P-256, ≠ CA key → mismatch negative
    set(MQ_MITM_V1_CA_CRT  "${MQ_CERT_DIR}/mitm-v1ca.crt")   # X509v1, NO extensions → must be rejected (no explicit basicConstraints)
    if(NOT EXISTS "${MQ_MITM_CA_CRT}" OR NOT EXISTS "${MQ_MITM_CA_KEY}"
       OR NOT EXISTS "${MQ_MITM_CA_ENC_KEY}"
       OR NOT EXISTS "${MQ_MITM_LEAF_CRT}" OR NOT EXISTS "${MQ_MITM_LEAF_KEY}"
       OR NOT EXISTS "${MQ_MITM_V1_CA_CRT}")
        find_program(OPENSSL_BIN openssl REQUIRED)
        file(MAKE_DIRECTORY "${MQ_CERT_DIR}")
        message(STATUS "Generating MITM CA/leaf fixtures in ${MQ_CERT_DIR}")
        # P-256 CA with basicConstraints CA:TRUE + keyUsage keyCertSign.
        execute_process(
            COMMAND ${OPENSSL_BIN} ecparam -name prime256v1 -genkey -noout -out "${MQ_MITM_CA_KEY}"
            RESULT_VARIABLE _rc1 OUTPUT_QUIET ERROR_QUIET)
        execute_process(
            COMMAND ${OPENSSL_BIN} req -x509 -new -key "${MQ_MITM_CA_KEY}"
                    -out "${MQ_MITM_CA_CRT}" -days 3650 -subj "/CN=mqproxy-mitm-test-ca"
                    -addext "basicConstraints=critical,CA:TRUE"
                    -addext "keyUsage=critical,keyCertSign,cRLSign"
            RESULT_VARIABLE _rc2 OUTPUT_QUIET ERROR_QUIET)
        # Encrypted copy of the CA key (passphrase "x") — create() must reject it.
        execute_process(
            COMMAND ${OPENSSL_BIN} ec -in "${MQ_MITM_CA_KEY}" -aes256 -passout pass:x
                    -out "${MQ_MITM_CA_ENC_KEY}"
            RESULT_VARIABLE _rc3 OUTPUT_QUIET ERROR_QUIET)
        # P-256 leaf with CA:FALSE (matched key) — the ONLY rejection reason is CA:FALSE.
        execute_process(
            COMMAND ${OPENSSL_BIN} ecparam -name prime256v1 -genkey -noout -out "${MQ_MITM_LEAF_KEY}"
            RESULT_VARIABLE _rc4 OUTPUT_QUIET ERROR_QUIET)
        execute_process(
            COMMAND ${OPENSSL_BIN} req -x509 -new -key "${MQ_MITM_LEAF_KEY}"
                    -out "${MQ_MITM_LEAF_CRT}" -days 3650 -subj "/CN=mqproxy-mitm-test-leaf"
                    -addext "basicConstraints=critical,CA:FALSE"
            RESULT_VARIABLE _rc5 OUTPUT_QUIET ERROR_QUIET)
        # X509v1 self-signed cert with NO extensions (CSR -> x509 -req with no
        # -extfile keeps it v1). X509_check_ca() treats a v1 cert as CA-eligible,
        # so this is the negative that proves the explicit-basicConstraints gate:
        # it has no BCONS extension and MUST be rejected. Signed by the CA key so
        # the ONLY rejection reason is the missing basicConstraints.
        execute_process(
            COMMAND ${OPENSSL_BIN} req -new -key "${MQ_MITM_CA_KEY}"
                    -subj "/CN=mqproxy-mitm-test-v1ca" -out "${MQ_CERT_DIR}/mitm-v1ca.csr"
            RESULT_VARIABLE _rc6 OUTPUT_QUIET ERROR_QUIET)
        execute_process(
            COMMAND ${OPENSSL_BIN} x509 -req -in "${MQ_CERT_DIR}/mitm-v1ca.csr"
                    -signkey "${MQ_MITM_CA_KEY}" -days 3650 -out "${MQ_MITM_V1_CA_CRT}"
            RESULT_VARIABLE _rc7 OUTPUT_QUIET ERROR_QUIET)
        if(NOT _rc1 EQUAL 0 OR NOT _rc2 EQUAL 0 OR NOT _rc3 EQUAL 0
           OR NOT _rc4 EQUAL 0 OR NOT _rc5 EQUAL 0
           OR NOT _rc6 EQUAL 0 OR NOT _rc7 EQUAL 0)
            message(FATAL_ERROR "openssl failed generating MITM CA/leaf fixtures")
        endif()
    endif()

    # Pass the fixture paths to the MITM unit suite (target created above, gated on
    # MQPROXY_MITM). The fixtures are defined here (after MQ_CERT_DIR), so we attach
    # the compile defs here rather than at the target block. Gate MUST match the
    # target-definition block above (MQPROXY_MITM) so the targets and their tests
    # appear/disappear together.
    if(MQPROXY_MITM)
        target_compile_definitions(test_mitm_core PRIVATE
            MITM_CA_CRT="${MQ_MITM_CA_CRT}"
            MITM_CA_KEY="${MQ_MITM_CA_KEY}"
            MITM_CA_ENC_KEY="${MQ_MITM_CA_ENC_KEY}"
            MITM_LEAF_CRT="${MQ_MITM_LEAF_CRT}"   # CA:FALSE matched pair → non-CA negative
            MITM_LEAF_KEY="${MQ_MITM_LEAF_KEY}"   # P-256 ≠ CA key → mismatch negative
            MITM_V1_CA_CRT="${MQ_MITM_V1_CA_CRT}") # X509v1 no-extensions → missing-basicConstraints negative

        # Task 8 smoke (mitm_smoke_server target created above): register here so
        # the MQ_MITM_CA_* fixture paths are populated. SKIP (77) iff openssl absent.
        add_test(NAME e2e_mitm_smoke
            COMMAND ${CMAKE_COMMAND} -E env
                MITM_SERVER_BIN=$<TARGET_FILE:mitm_smoke_server>
                MITM_CA_CRT=${MQ_MITM_CA_CRT} MITM_CA_KEY=${MQ_MITM_CA_KEY}
                bash ${CMAKE_SOURCE_DIR}/tests/integration/e2e_mitm_smoke.sh)
        set_tests_properties(e2e_mitm_smoke PROPERTIES SKIP_RETURN_CODE 77)
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

    # Phase 5c Task 3: mq_server_active_conn lifecycle (set on accept, cleared on
    # close). Real client+server on a shared base, so it needs the test cert.
    add_executable(test_metrics_active_conn tests/integration/test_metrics_active_conn.c)
    target_link_libraries(test_metrics_active_conn
        mqproxy xquic ${EVENT_CORE_LIB} ${EVENT_EXTRA_LIB} pthread dl m stdc++)
    target_include_directories(test_metrics_active_conn PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_metrics_active_conn PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_metrics_active_conn PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_metrics_active_conn COMMAND test_metrics_active_conn)

    # --max-conns engine-wide connection cap: falsifiable real client+server proof
    # (A admitted, B refused, A closed→slot frees, C re-admitted). Needs the cert.
    add_executable(test_max_conns_e2e tests/integration/test_max_conns_e2e.c)
    target_link_libraries(test_max_conns_e2e
        mqproxy xquic ${EVENT_CORE_LIB} ${EVENT_EXTRA_LIB} pthread dl m stdc++)
    target_include_directories(test_max_conns_e2e PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_max_conns_e2e PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_max_conns_e2e PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_max_conns_e2e COMMAND test_max_conns_e2e)

    # UDP relay server-side full-path integration (Task 5.3): real client+server
    # over loopback UDP + a local UDP echo socket; the test drives 0x02 streams
    # and DATAGRAM frames directly on the client conn (no client UDP ingress yet).
    add_executable(test_udp_relay tests/integration/test_udp_relay.c)
    target_link_libraries(test_udp_relay
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_udp_relay PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_udp_relay PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_udp_relay PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_udp_relay COMMAND test_udp_relay)

    # Client reconnect + keepalive integration (Phase 5b, Task 4.3): real
    # client+server over loopback with RECONNECT ENABLED; drops the tunnel conn
    # via mq_conn_close and proves reconnect/re-auth + queue carry-over + UDP
    # rebind + free-while-reconnecting (ASan) + keepalive hold, end-to-end.
    add_executable(test_client_reconnect tests/integration/test_client_reconnect.c)
    target_link_libraries(test_client_reconnect
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_client_reconnect PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_client_reconnect PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_client_reconnect PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_client_reconnect COMMAND test_client_reconnect)

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

    # Gateway client reconnect (Task 5.2, Phase 5b): in-process proof that the
    # gw_client reconnect path re-establishes the H3 tunnel on loss and a fresh
    # fetch completes end-to-end. Same real client+server H3-over-loopback fixture
    # as the gateway-client cases in test_gw_client, so it needs the cert/key
    # defines too.
    add_executable(test_gw_reconnect tests/integration/test_gw_reconnect.c)
    target_link_libraries(test_gw_reconnect
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_gw_reconnect PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_gw_reconnect PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_gw_reconnect PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_gw_reconnect COMMAND test_gw_reconnect)

    # Neutral intake boundary relay test (Task 5, Phase 7 MITM Slice 0+1):
    # drives mq_gw_client_prevalidate / mq_gw_client_req_begin / req_body /
    # req_body_done / req_aborted / req_drained directly with a fake
    # mq_gw_sink_ops_t (no fetch adapter / fetch listener), locking the
    # boundary a future H2/H3 MITM adapter will also rely on.
    add_executable(test_gw_relay tests/integration/test_gw_relay.c)
    target_link_libraries(test_gw_relay
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_gw_relay PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_gw_relay PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_gw_relay PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_gw_relay COMMAND test_gw_relay)

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

    add_executable(test_datagram_fabric tests/integration/test_datagram_fabric.c)
    target_link_libraries(test_datagram_fabric
        mqproxy
        xquic
        ${EVENT_CORE_LIB}
        ${EVENT_EXTRA_LIB}
        pthread dl m stdc++)
    target_include_directories(test_datagram_fabric PRIVATE tests src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    target_compile_definitions(test_datagram_fabric PRIVATE
        TEST_CERT_FILE="${MQ_CERT_FILE}"
        TEST_KEY_FILE="${MQ_KEY_FILE}")
    set_target_properties(test_datagram_fabric PROPERTIES
        BUILD_RPATH "${XQUIC_BUILD_DIR}")
    add_test(NAME test_datagram_fabric COMMAND test_datagram_fabric)

    # ---- mqproxy CLI (client/server binaries) ----
    # The static library target is also named `mqproxy`; give the executable a
    # distinct target name but emit it as the `mqproxy` binary.
    add_executable(mqproxy_cli cli/main.c)
    set_target_properties(mqproxy_cli PROPERTIES OUTPUT_NAME mqproxy)
    # Surface project(VERSION) into the binary so `mqproxy --version` self-identifies.
    target_compile_definitions(mqproxy_cli PRIVATE MQPROXY_VERSION="${PROJECT_VERSION}")
    if(MQPROXY_STATIC_XQUIC)
        # Self-contained binary for packaging: statically link xquic + the BoringSSL
        # it was built against (libxquic-static.a leaves ~118 BoringSSL SSL_*/EVP_AEAD_*/
        # CRYPTO_BUFFER_* symbols undefined; system OpenSSL does not export these QUIC
        # APIs, so they must resolve against BoringSSL's static archives). No BUILD_RPATH:
        # nothing non-standard is loaded at runtime (the residual libssl.so.3 in ldd is
        # libcurl's, not xquic's).
        if(NOT TARGET xquic-static)
            message(FATAL_ERROR
                "MQPROXY_STATIC_XQUIC=ON but xquic-static was not imported "
                "(no libxquic-static.a at ${XQUIC_BUILD_DIR}).")
        endif()
        set(_bssl_ssl    "${MQPROXY_BORINGSSL_DIR}/libssl.a")
        set(_bssl_crypto "${MQPROXY_BORINGSSL_DIR}/libcrypto.a")
        if(NOT EXISTS "${_bssl_ssl}" OR NOT EXISTS "${_bssl_crypto}")
            message(FATAL_ERROR
                "MQPROXY_STATIC_XQUIC=ON but BoringSSL static archives not found at "
                "${MQPROXY_BORINGSSL_DIR} (expected libssl.a + libcrypto.a). Build xquic "
                "via scripts/build-xquic.sh or set -DMQPROXY_BORINGSSL_DIR=<dir>.")
        endif()
        # nghttp2 static archive (Slice 3 Task 4): the live H2 MITM adapter links it.
        # nghttp2 is a leaf (no BoringSSL/xquic symbols), so link order is unconstrained
        # and no symbol isolation is needed. Require the .a in this packaging build;
        # mirror the BoringSSL archive-missing gate above with an actionable message.
        if(NOT NGHTTP2_STATIC_LIB)
            message(FATAL_ERROR
                "MQPROXY_STATIC_XQUIC=ON but libnghttp2.a was not found (only the "
                "shared library is installed). The static build links the H2 MITM "
                "adapter against it. Install the nghttp2 static archive (Debian/Ubuntu: "
                "libnghttp2-dev ships it as /usr/lib/<multiarch>/libnghttp2.a; on some "
                "distros it is a separate -static package), or build the dynamic "
                "binary (omit -DMQPROXY_STATIC_XQUIC=ON).")
        endif()
        # Link order: xquic-static references BoringSSL symbols, so the archives follow it.
        # NOTE: the raw archives (not mq_boringssl) are linked here because they must
        # appear AFTER xquic-static to satisfy its undefined BoringSSL QUIC symbols;
        # the MITM core's SSL_*/X509_* resolve against the very same objects. Symbol
        # isolation (--exclude-libs) is applied below for both branches.
        target_link_libraries(mqproxy_cli
            mqproxy
            xquic-static
            "${_bssl_ssl}" "${_bssl_crypto}"
            "${NGHTTP2_STATIC_LIB}"
            ${EVENT_CORE_LIB}
            ${EVENT_EXTRA_LIB}
            pthread dl m stdc++)
        target_include_directories(mqproxy_cli PRIVATE ${NGHTTP2_INCLUDE_DIRS})
    else()
        # Dynamic build: libxquic.so bakes its BoringSSL in internally, so the exe
        # has no BoringSSL objects today. Link mq_boringssl so the MITM core's
        # SSL_*/X509_* can resolve once a caller references them (Task 13). When the
        # archives are absent, mq_boringssl does not exist and MITM is compiled out
        # (MQ_MITM_AVAILABLE=0 below), so nothing references BoringSSL → clean link.
        target_link_libraries(mqproxy_cli
            mqproxy
            xquic
            ${NGHTTP2_LIBRARIES}
            ${EVENT_CORE_LIB}
            ${EVENT_EXTRA_LIB}
            pthread dl m stdc++)
        target_include_directories(mqproxy_cli PRIVATE ${NGHTTP2_INCLUDE_DIRS})
        if(MQ_HAVE_BORINGSSL_ARCHIVES)
            target_link_libraries(mqproxy_cli mq_boringssl)
        endif()
        set_target_properties(mqproxy_cli PROPERTIES BUILD_RPATH "${XQUIC_BUILD_DIR}")
    endif()

    # ---- MITM availability + BoringSSL symbol isolation (Slice 3 Task 3) -------
    # MQ_MITM_AVAILABLE is the fail-closed gate: the live MITM path is compiled in
    # ONLY when the BoringSSL archives are present. All MITM references in cli/main.c
    # must be wrapped in `#if MQ_MITM_AVAILABLE` (added in Task 13) so a no-archive
    # build pulls NO MITM symbols and therefore LINKS — a runtime branch alone would
    # fail at link time. When unavailable, `--mitm` errors at startup and exits != 0.
    # MQPROXY_MITM (CMake var, set in BuildSetup.cmake) gates whether the live MITM
    # path is compiled in; MQ_MITM_AVAILABLE is the matching C compile-definition.
    if(MQPROXY_MITM)
        target_compile_definitions(mqproxy_cli PRIVATE MQ_MITM_AVAILABLE=1)
        # Task 10: src/mitm/mq_mitm_conn.c (live orchestrator) is compiled into the
        # mqproxy LIB under MQPROXY_MITM (see ~line 71), which mqproxy_cli links —
        # no per-cli target_sources needed. Task 13 wires it into cli/main.c under
        # `#if MQ_MITM_AVAILABLE`.
        #
        # Isolate the BoringSSL the MITM core links against so its SSL_*/X509_*/EVP_*
        # cannot interpose libcurl's system OpenSSL (libssl.so) at runtime. Both the
        # static branch (raw archives) and the dynamic branch (mq_boringssl) pull
        # libssl.a/libcrypto.a by name, so --exclude-libs by archive base-name hides
        # all their global symbols (makes them link-local). GNU ld + lld (Linux) only;
        # applied to mqproxy_cli ONLY — the test targets MAY export (they link
        # mq_boringssl directly without this flag). Verified by ctest
        # check_boringssl_isolation.
        target_link_options(mqproxy_cli PRIVATE
            -Wl,--exclude-libs,libssl.a
            -Wl,--exclude-libs,libcrypto.a)
    else()
        target_compile_definitions(mqproxy_cli PRIVATE MQ_MITM_AVAILABLE=0)
    endif()
    target_include_directories(mqproxy_cli PRIVATE src
        ${XQUIC_INCLUDE_DIR} ${EVENT_INCLUDE_DIR})
    # The installed binary has NO bundled default cert/key: `server` always
    # requires explicit --cert/--key (the committed tests/certs/* are public
    # test fixtures and must never be a shipped server's default identity).

    # CLI help / smoke test (shell): asserts --help works and unknown
    # subcommands fail. Passes the binary path via $<TARGET_FILE:mqproxy>.
    add_test(NAME test_cli_help
        COMMAND ${CMAKE_COMMAND} -E env
            sh ${CMAKE_SOURCE_DIR}/tests/test_cli_help.sh $<TARGET_FILE:mqproxy_cli>)

    # ---- BoringSSL symbol-isolation gate (Slice 3 Task 3) ----
    # Asserts the BoringSSL the MITM core links against is NOT exported from the
    # mqproxy exe (cannot interpose libcurl's system OpenSSL), no undefined SSL_*
    # remains, and libcurl still dynamically needs libssl.so. Gated on the archives
    # since --exclude-libs / the MITM link only apply then. See the script header
    # for why the checks tolerate symbol ABSENCE (static vs dynamic build).
    if(MQ_HAVE_BORINGSSL_ARCHIVES)
        add_test(NAME check_boringssl_isolation
            COMMAND bash ${CMAKE_SOURCE_DIR}/tests/integration/check_boringssl_isolation.sh
                $<TARGET_FILE:mqproxy_cli>)
    endif()

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

    # ---- Phase 7 Slice 0+1: transparent capture + opaque relay e2e ----
    # Drives the transparent-capture (REDIRECT) path end-to-end against a real
    # python3 TLS origin on 127.0.0.1:443:
    #   case 1: TLS opacity proof — curl as nobody through the nft REDIRECT rule
    #           → tunnel → server relay → origin; curl verifies the origin's cert
    #           (--cacert origin.crt); a MITM would break cert verification.
    #   case 2: (NET_ADMIN) 2-path multipath smoke — same capture with tc shaping.
    #   case 3: teardown assertion — nft table gone after client exit.
    # REQUIRES root + CAP_NET_ADMIN (nft + IP_TRANSPARENT + port 443).
    # Exits 77 (SKIP) when not root, nft absent, or no CAP_NET_ADMIN in container.
    add_test(NAME e2e_tproxy
        COMMAND ${CMAKE_COMMAND} -E env
            MQPROXY_BIN=$<TARGET_FILE:mqproxy_cli>
            MQPROXY_CERT=${MQ_CERT_FILE}
            MQPROXY_KEY=${MQ_KEY_FILE}
            MQPROXY_ORIGIN_CERT=${MQ_ORIGIN_CERT_FILE}
            MQPROXY_ORIGIN_KEY=${MQ_ORIGIN_KEY_FILE}
            bash ${CMAKE_SOURCE_DIR}/tests/integration/e2e_tproxy.sh)
    set_tests_properties(e2e_tproxy PROPERTIES SKIP_RETURN_CODE 77)

    # ---- Phase 7 Slice 3 Task 16: NET_ADMIN transparent-MITM H2 e2e ----
    # The capstone for the 🔒 security gate: the ONLY test that drives the LIVE
    # mq_mitm_conn orchestrator end-to-end. curl --http2 is transparently captured
    # (nft REDIRECT), the client forges a per-SNI leaf signed by the MITM CA,
    # terminates TLS, speaks h2 over the tunnel to the gateway server, which
    # fetches the real origin via libcurl. Asserts:
    #   (a) transparent MITM works (h2 200 against the forged leaf trusted via the
    #       MITM CA; a non-MITM relay would present the origin cert and be rejected),
    #   (b) cache HIT — a second fetch is served origin-once (origin /__count == 1),
    #   (c) a cookie-authenticated request reaches the origin WITH its Cookie (§4.5),
    #   (d) an --ignore-host SNI is spliced OPAQUELY (origin cert verifies; the MITM
    #       CA is REJECTED — no forged leaf presented for the excluded host),
    #   (e) concurrent multi-stream fetch succeeds (N streams on one h2 conn).
    # REQUIRES root + CAP_NET_ADMIN (nft) + curl(--http2) + openssl + python3 + a
    # MITM-capable binary. Exits 77 (SKIP) when any of those is absent (mirrors
    # e2e_tproxy). Gated on MQPROXY_MITM so it only registers for a MITM build; the
    # MITM CA fixtures (MQ_MITM_CA_*) and a runtime-minted origin cert drive it.
    if(MQPROXY_MITM)
        add_test(NAME e2e_mitm_h2
            COMMAND ${CMAKE_COMMAND} -E env
                MQPROXY_BIN=$<TARGET_FILE:mqproxy_cli>
                MQPROXY_CERT=${MQ_CERT_FILE}
                MQPROXY_KEY=${MQ_KEY_FILE}
                MQ_MITM_CA_CRT=${MQ_MITM_CA_CRT}
                MQ_MITM_CA_KEY=${MQ_MITM_CA_KEY}
                bash ${CMAKE_SOURCE_DIR}/tests/integration/e2e_mitm_h2.sh)
        set_tests_properties(e2e_mitm_h2 PROPERTIES SKIP_RETURN_CODE 77)
    endif()

    # ---- Phase 3 Task 7.1: e2e UDP relay test utilities ----
    # These are standalone CLI helpers driven by e2e_udp.sh (Task 7.2).
    # They are NOT registered as ctest tests (no add_test).

    # udp_echo: binds 127.0.0.1:<port>, echoes every datagram back to sender.
    # No mqproxy dependency — pure POSIX sockets.
    add_executable(udp_echo tests/integration/udp_echo.c)
    target_include_directories(udp_echo PRIVATE tests)

    # udpsocks: SOCKS5 UDP ASSOCIATE client; links mqproxy for
    # mq_socks5_build_udp_hdr / mq_socks5_parse_udp_hdr.
    add_executable(udpsocks tests/integration/udpsocks.c)
    target_link_libraries(udpsocks mqproxy)
    target_include_directories(udpsocks PRIVATE tests src)

    # ---- Phase 3 Task 7.2: e2e UDP relay end-to-end scenarios ----
    # Drives the full UDP relay path against udp_echo using udpsocks:
    #   case 1: 64-byte byte-exact echo.
    #   case 2: 3000-byte echo + frags_reassembled > 0 from server stats.
    #   case 3: two concurrent targets, both byte-exact.
    #   case 4: idle-timeout 1s expiry → re-OPEN path.
    #   case 5: kill udpsocks mid-flight → server reaps; health check.
    #   case 6: (NET_ADMIN) 2-path smoke, both paths carried bytes.
    # Cases 1-5 run anywhere; case 6 needs tc on lo and is skipped (a note)
    # without NET_ADMIN. The WHOLE script exits 77 (SKIP) ONLY when required
    # binaries (mqproxy, udpsocks, udp_echo) or certs are missing.
    add_test(NAME e2e_udp
        COMMAND ${CMAKE_COMMAND} -E env
            MQPROXY_BIN=$<TARGET_FILE:mqproxy_cli>
            UDPSOCKS_BIN=$<TARGET_FILE:udpsocks>
            UDPECHO_BIN=$<TARGET_FILE:udp_echo>
            MQPROXY_CERT=${MQ_CERT_FILE}
            MQPROXY_KEY=${MQ_KEY_FILE}
            bash ${CMAKE_SOURCE_DIR}/tests/integration/e2e_udp.sh)
    set_tests_properties(e2e_udp PROPERTIES SKIP_RETURN_CODE 77)

    # ---- packaging / install ----
    configure_file(packaging/systemd/mqproxy-server@.service.in
        ${CMAKE_BINARY_DIR}/packaging/mqproxy-server@.service @ONLY)
    configure_file(packaging/systemd/mqproxy-client@.service.in
        ${CMAKE_BINARY_DIR}/packaging/mqproxy-client@.service @ONLY)

    install(TARGETS mqproxy_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    # systemd units / sysusers / tmpfiles are NOT multiarch — literal lib/ paths.
    install(FILES
        ${CMAKE_BINARY_DIR}/packaging/mqproxy-server@.service
        ${CMAKE_BINARY_DIR}/packaging/mqproxy-client@.service
        DESTINATION lib/systemd/system)
    install(FILES packaging/sysusers.d/mqproxy.conf  DESTINATION lib/sysusers.d)
    install(FILES packaging/tmpfiles.d/mqproxy.conf  DESTINATION lib/tmpfiles.d)

    install(FILES server.conf.example client.conf.example
        DESTINATION ${CMAKE_INSTALL_DOCDIR})

    # License bundling (Apache-2.0 §4(a)). The binary statically links xquic AND
    # BoringSSL, so both LICENSEs are mandatory. OPTIONAL only so CI jobs that skip
    # the xquic submodule don't fail the install rule.
    install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})
    install(FILES third_party/xquic/LICENSE
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/third-party RENAME xquic.txt OPTIONAL)
    install(FILES third_party/xquic/third_party/boringssl/LICENSE
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/third-party RENAME boringssl.txt OPTIONAL)

    # Verify the install layout + static self-containment. SKIPs (77) unless the
    # build was configured with -DCMAKE_INSTALL_PREFIX=/usr (packaging build).
    add_test(NAME packaging_install_static
        COMMAND bash ${CMAKE_SOURCE_DIR}/tests/packaging/verify_install.sh
                ${CMAKE_BINARY_DIR})
    set_tests_properties(packaging_install_static PROPERTIES SKIP_RETURN_CODE 77)
endif()
