# BuildSetup.cmake — compiler standards, optional deps, sanitizer flags

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---------- xquic ----------
#
# QLOG REQUIREMENT (read this if test_qlog_blocked or e2e_multipath fail):
#   The qlog-based milestone 1-B benchmark (tests/integration/e2e_multipath.sh)
#   and the `test_qlog_blocked` unit test assert on xquic qlog EXTRA-importance
#   events (frames_processed, xqc_parse_*_blocked_frame). Those events are ONLY
#   emitted when the linked xquic was compiled with -DXQC_ENABLE_EVENT_LOG=ON.
#   Against a stock xquic build those assertions are vacuous or fail.
#
#   Build a qlog-enabled xquic for mqproxy by running:
#       scripts/build-xquic.sh
#   then configure with:
#       -DXQUIC_BUILD_DIR=${CMAKE_SOURCE_DIR}/third_party/xquic/build
#   or point XQUIC_BUILD_DIR at any other XQC_ENABLE_EVENT_LOG=ON build.
set(XQUIC_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/third_party/xquic/include)

set(XQUIC_BUILD_DIR "" CACHE PATH "Path to pre-built xquic build directory")

# Hint string shown whenever XQUIC_BUILD_DIR is unset or the lib looks like it
# was built WITHOUT qlog (XQC_ENABLE_EVENT_LOG). Kept as one variable so both
# branches below print the same actionable guidance.
set(_xquic_qlog_hint
    "  qlog-based tests (test_qlog_blocked, e2e_multipath) need an xquic built\n"
    "  with -DXQC_ENABLE_EVENT_LOG=ON. Run scripts/build-xquic.sh, then set\n"
    "  -DXQUIC_BUILD_DIR=${CMAKE_SOURCE_DIR}/third_party/xquic/build\n"
    "  (or point XQUIC_BUILD_DIR at any XQC_ENABLE_EVENT_LOG=ON build).")

if(XQUIC_BUILD_DIR)
    message(STATUS "Using pre-built xquic from: ${XQUIC_BUILD_DIR}")
    add_library(xquic SHARED IMPORTED)
    set_target_properties(xquic PROPERTIES
        IMPORTED_LOCATION "${XQUIC_BUILD_DIR}/libxquic.so"
    )
    if(EXISTS "${XQUIC_BUILD_DIR}/libxquic-static.a")
        add_library(xquic-static STATIC IMPORTED)
        set_target_properties(xquic-static PROPERTIES
            IMPORTED_LOCATION "${XQUIC_BUILD_DIR}/libxquic-static.a"
        )
    endif()

    # Best-effort qlog-enabled probe: a build with XQC_ENABLE_EVENT_LOG=ON
    # embeds the EXTRA-importance frame-tracing markers (e.g. "frames_processed")
    # in libxquic.so. If we can read the lib and the marker is absent, warn that
    # the qlog tests will not behave as expected.
    set(_xquic_lib "${XQUIC_BUILD_DIR}/libxquic.so")
    if(EXISTS "${_xquic_lib}")
        file(STRINGS "${_xquic_lib}" _xquic_qlog_marker
             REGEX "frames_processed" LIMIT_COUNT 1)
        if(NOT _xquic_qlog_marker)
            message(STATUS
                "xquic at ${XQUIC_BUILD_DIR} appears to LACK qlog "
                "(XQC_ENABLE_EVENT_LOG=ON) — no 'frames_processed' marker found.\n"
                "${_xquic_qlog_hint}")
        endif()
    endif()
else()
    message(STATUS "XQUIC_BUILD_DIR not set — xquic targets not imported.\n"
                   "${_xquic_qlog_hint}")
endif()

# ---------- libevent ----------
find_path(EVENT_INCLUDE_DIR event2/event.h)
find_library(EVENT_CORE_LIB event_core)
find_library(EVENT_EXTRA_LIB event_extra)

if(NOT EVENT_CORE_LIB)
    message(WARNING "libevent_core not found — some targets may fail to link. "
                    "Install: apt install libevent-dev")
endif()

# ---------- HTTP/3-capable libcurl (opt-in) ----------
#
# Default build links the system libcurl (no HTTP/3). To speak h3 to an origin
# (X-Mq-Origin-Protocol: h3), point this at the install prefix produced by
# scripts/build-h3-curl.sh (ngtcp2 + nghttp3 + libcurl on the pinned BoringSSL):
#       -DMQPROXY_H3_CURL=${CMAKE_SOURCE_DIR}/third_party/h3-curl/install
# When set, CMakeLists.txt defines the CURL::libcurl imported target from that
# prefix instead of find_package(CURL). Unset = system libcurl, unchanged.
set(MQPROXY_H3_CURL "" CACHE PATH "Install prefix of an HTTP/3-capable libcurl (scripts/build-h3-curl.sh)")

# ---------- Sanitizers ----------
option(MQPROXY_SANITIZE "Enable ASan + UBSan" OFF)

if(MQPROXY_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()
