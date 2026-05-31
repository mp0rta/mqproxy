# BuildSetup.cmake — compiler standards, optional deps, sanitizer flags

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---------- xquic ----------
set(XQUIC_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/third_party/xquic/include)

option(XQUIC_BUILD_DIR "Path to pre-built xquic build directory" "")

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
else()
    message(STATUS "XQUIC_BUILD_DIR not set — xquic targets not imported")
endif()

# ---------- libevent ----------
find_path(EVENT_INCLUDE_DIR event2/event.h)
find_library(EVENT_CORE_LIB event_core)
find_library(EVENT_EXTRA_LIB event_extra)

if(NOT EVENT_CORE_LIB)
    message(WARNING "libevent_core not found — some targets may fail to link. "
                    "Install: apt install libevent-dev")
endif()

# ---------- Sanitizers ----------
option(MQPROXY_SANITIZE "Enable ASan + UBSan" OFF)

if(MQPROXY_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()
