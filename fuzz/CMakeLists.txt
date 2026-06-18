# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta
#
# Standalone libFuzzer project for the wire/ingress parse surface.
# Deliberately its OWN project() so configuring it never triggers the root
# CMakeLists.txt's find_package(CURL REQUIRED) / xquic wiring — the in-scope
# parsers depend only on libc, so no submodule build is needed.
#
#   cmake -S fuzz -B build-fuzz -DCMAKE_C_COMPILER=clang
#   cmake --build build-fuzz
cmake_minimum_required(VERSION 3.10)
project(mqproxy_fuzz LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "fuzz/ requires clang (libFuzzer). Configure with -DCMAKE_C_COMPILER=clang.")
endif()

set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/../src)
set(FUZZ_FLAGS -g -O1 -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)

# define_fuzzer(<name> <harness.c> <extra src TUs...>)
function(define_fuzzer name harness)
    add_executable(${name} ${harness} ${ARGN})
    target_include_directories(${name} PRIVATE ${SRC})
    target_compile_options(${name} PRIVATE ${FUZZ_FLAGS})
    target_link_options(${name} PRIVATE ${FUZZ_FLAGS})
endfunction()

set(WIRE ${SRC}/wire/mq_wire.c ${SRC}/wire/mq_varint.c)

define_fuzzer(fuzz_varint fuzz_varint.c ${SRC}/wire/mq_varint.c)

define_fuzzer(fuzz_wire_auth_req          fuzz_wire_auth_req.c          ${WIRE})
define_fuzzer(fuzz_wire_auth_resp         fuzz_wire_auth_resp.c         ${WIRE})
define_fuzzer(fuzz_wire_connect_tcp_req   fuzz_wire_connect_tcp_req.c   ${WIRE})
define_fuzzer(fuzz_wire_connect_tcp_resp  fuzz_wire_connect_tcp_resp.c  ${WIRE})
define_fuzzer(fuzz_wire_udp_session_open  fuzz_wire_udp_session_open.c  ${WIRE})
define_fuzzer(fuzz_wire_udp_session_resp  fuzz_wire_udp_session_resp.c  ${WIRE})
define_fuzzer(fuzz_udp_msg_hdr            fuzz_udp_msg_hdr.c            ${SRC}/wire/mq_udp_msg.c)

# fuzz/scripts/gen_wire_seeds.c is NOT a build target — it is a standalone helper
# compiled by hand (see its header comment) only when (re)generating wire seeds.

set(INGRESS ${SRC}/ingress/mq_socks5.c ${WIRE})
define_fuzzer(fuzz_socks5_feed     fuzz_socks5_feed.c     ${INGRESS})
define_fuzzer(fuzz_socks5_udp_hdr  fuzz_socks5_udp_hdr.c  ${INGRESS})
define_fuzzer(fuzz_http_connect    fuzz_http_connect.c    ${SRC}/ingress/mq_http_connect.c ${WIRE})
define_fuzzer(fuzz_clienthello     fuzz_clienthello.c     ${SRC}/ingress/mq_clienthello.c)
