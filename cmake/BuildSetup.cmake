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

# Static-link xquic + its BoringSSL into shipped binaries (packaging). Default OFF
# keeps the dynamic build + all test executables on the shared libxquic.so.
option(MQPROXY_STATIC_XQUIC "Statically link libxquic-static.a + BoringSSL into mqproxy (packaging)" OFF)
# BoringSSL static archives that libxquic-static.a was built against. Default matches
# the in-tree scripts/build-xquic.sh layout; override for out-of-tree xquic builds.
set(MQPROXY_BORINGSSL_DIR "${XQUIC_BUILD_DIR}/../third_party/boringssl/build"
    CACHE PATH "Dir containing BoringSSL libssl.a/libcrypto.a for static linking")

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

# ---------- BoringSSL (vendored under xquic) for the MITM core ----------
set(MQPROXY_BORINGSSL_INCLUDE_DIR "${MQPROXY_BORINGSSL_DIR}/../include"
    CACHE PATH "BoringSSL include dir (must track MQPROXY_BORINGSSL_DIR)")
set(MQ_HAVE_BORINGSSL_ARCHIVES OFF)
if(EXISTS "${MQPROXY_BORINGSSL_DIR}/libssl.a" AND
   EXISTS "${MQPROXY_BORINGSSL_DIR}/libcrypto.a")
    set(MQ_HAVE_BORINGSSL_ARCHIVES ON)
endif()

# Derived MITM availability flag: the live MITM L7 path (Phase 7 Slice 3) needs
# the BoringSSL static archives the MITM core links against. Kept as its own
# name so call sites read intent ("is MITM compiled in?") rather than re-deriving
# the archive predicate, and so a future decoupling has one place to change.
set(MQPROXY_MITM ${MQ_HAVE_BORINGSSL_ARCHIVES})

# ---- mq_boringssl: single source of truth for the BoringSSL static-link recipe.
# Hoisted here (out of the test-only block in CMakeLists.txt) so it exists
# whenever the archives are present, independent of which targets consume it:
# the MITM unit/smoke test targets AND mqproxy_cli (the live MITM path) all link
# it. Archive ORDER matters (libssl.a before libcrypto.a). NO xquic here: the
# MITM core is sans-io / BoringSSL-only and references no xqc_* symbols, so the
# static archive pulls no xquic-dependent objects — keep it xquic-free.
if(MQ_HAVE_BORINGSSL_ARCHIVES AND NOT TARGET mq_boringssl)
    add_library(mq_boringssl INTERFACE)
    target_link_libraries(mq_boringssl INTERFACE
        "${MQPROXY_BORINGSSL_DIR}/libssl.a"
        "${MQPROXY_BORINGSSL_DIR}/libcrypto.a"
        pthread dl m stdc++)
    target_include_directories(mq_boringssl INTERFACE
        ${MQPROXY_BORINGSSL_INCLUDE_DIR})
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
