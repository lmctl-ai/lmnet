cmake_minimum_required(VERSION 3.24)
project(lmnet VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(LMNET_FULL_STATIC "Link the complete executable statically" ON)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(LMNET_HOST_SCHEMA "${CMAKE_CURRENT_SOURCE_DIR}/schema/lmnet.host.json")

# ---- vendored iputils subset ------------------------------------------------
# third_party/iputils is git-ignored and synced by scripts/sync-iputils.sh,
# pinned by iputils.lock. The tool mains are renamed (main=lmnet_*_main) so
# the CLI can dispatch to them; see THIRD_PARTY_NOTICES.md for licenses
# (ping BSD-3-Clause, tracepath GPL-2.0-or-later).
set(IPUTILS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/iputils")
set(IPUTILS_SOURCES
  ping/ping.c
  ping/ping_common.c
  ping/ping6_common.c
  ping/node_info.c
  tracepath.c
  iputils_common.c
  md5.c
)
list(TRANSFORM IPUTILS_SOURCES PREPEND "${IPUTILS_ROOT}/")

# ---- vendored iperf3 subset -------------------------------------------------
# third_party/iperf3 is git-ignored and synced by scripts/sync-iperf3.sh,
# pinned by iperf3.lock. The engine is built without OpenSSL (iperf's
# --with-openssl off by default) and without SCTP (--with-sctp off by
# default): our cpp/iperf3shim/iperf_config.h mirrors what the pinned
# tarball's ./configure --without-openssl generates. main.c is kept separate
# so it can be renamed like the iputils mains; see THIRD_PARTY_NOTICES.md
# for the license (BSD-3-Clause).
set(IPERF3_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/iperf3")
set(IPERF3_SOURCES
  cjson.c
  dscp.c
  iperf_api.c
  iperf_auth.c
  iperf_client_api.c
  iperf_error.c
  iperf_locale.c
  iperf_pthread.c
  iperf_sctp.c
  iperf_server_api.c
  iperf_tcp.c
  iperf_time.c
  iperf_udp.c
  iperf_util.c
  net.c
  tcp_info.c
  timer.c
  units.c
)
list(TRANSFORM IPERF3_SOURCES PREPEND "${IPERF3_ROOT}/src/")
set(IPERF3_MAIN "${IPERF3_ROOT}/src/main.c")

# ---- exact host-only schema; std is implicit in compiler 0.2.420 ----
set(SCHEMA_JSON "${CMAKE_CURRENT_SOURCE_DIR}/schema/lmnet.dsl.json")
configure_file("${LMNET_HOST_SCHEMA}" "${SCHEMA_JSON}" COPYONLY)
set(GENERATED_DIR "${CMAKE_BINARY_DIR}/generated")
set(GENERATED_SCHEMA "${GENERATED_DIR}/schema_embedded.hpp")
add_custom_command(
  OUTPUT "${GENERATED_SCHEMA}"
  COMMAND "${CMAKE_COMMAND}"
    -DINPUT="${SCHEMA_JSON}"
    -DOUTPUT="${GENERATED_SCHEMA}"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_schema.cmake"
  DEPENDS "${SCHEMA_JSON}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_schema.cmake"
  COMMENT "Embedding schema/lmnet.dsl.json"
)
add_custom_target(lmnet_schema DEPENDS "${GENERATED_SCHEMA}")

add_executable(lmnet
  cpp/main.cpp
  cpp/net.cpp
  cpp/dns.cpp
  cpp/sockets.cpp
  cpp/route.cpp
  cpp/neigh.cpp
  cpp/link.cpp
  cpp/rule.cpp
  cpp/counters.cpp
  cpp/trace.cpp
  ${IPUTILS_SOURCES}
  ${IPERF3_SOURCES}
  ${IPERF3_MAIN}
  "${GENERATED_SCHEMA}"
)
add_dependencies(lmnet lmnet_schema)

# cpp/iputilsshim/ (our config.h stand-in) shadows upstream; otherwise the
# include layout mirrors the iputils build. cpp/iperf3shim/ is first so the
# vendored iperf3 sources pick up our iperf_config.h/version.h stand-ins.
target_include_directories(lmnet PRIVATE
  cpp/iperf3shim
  cpp/iputilsshim
  cpp
  "${IPUTILS_ROOT}"
  "${IPERF3_ROOT}/src"
  "${GENERATED_DIR}"
)
# Rename each tool's main so the CLI can dispatch to it. Per-file: ping.c and
# tracepath.c both define main() and must land on distinct symbols.
set_source_files_properties("${IPUTILS_ROOT}/ping/ping.c" PROPERTIES
  COMPILE_DEFINITIONS "main=lmnet_ping_main"
)
set_source_files_properties("${IPUTILS_ROOT}/tracepath.c" PROPERTIES
  COMPILE_DEFINITIONS "main=lmnet_tracepath_main"
)
set_source_files_properties("${IPERF3_MAIN}" PROPERTIES
  COMPILE_DEFINITIONS "main=lmnet_iperf3_main"
)
# ping_common.c (iputils) and iperf_api.c (iperf3) both export a global
# usage(); rename iperf's so the two vendored engines coexist in one binary.
set_source_files_properties("${IPERF3_ROOT}/src/iperf_api.c" PROPERTIES
  COMPILE_DEFINITIONS "usage=lmnet_iperf3_usage"
)
# iputils sources are third-party: silence their warnings, keep ours strict.
# meson force-includes git-version.h (-include); our shim dir supplies it.
set_source_files_properties(${IPUTILS_SOURCES} PROPERTIES
  COMPILE_OPTIONS "-w;-include;git-version.h"
)
# iperf3 sources are third-party too: silence their warnings as well.
set_source_files_properties(${IPERF3_SOURCES} ${IPERF3_MAIN} PROPERTIES
  COMPILE_OPTIONS "-w"
)
find_package(Threads REQUIRED)
target_link_libraries(lmnet PRIVATE Threads::Threads m rt)
target_compile_options(lmnet PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(lmnet PRIVATE LMNET_VERSION="${PROJECT_VERSION}")

# Static linking: no runtime dependency beyond the OS C library.
if((CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang") AND NOT APPLE)
  target_link_options(lmnet PRIVATE -static-libstdc++ -static-libgcc)
  if(LMNET_FULL_STATIC)
    target_link_options(lmnet PRIVATE -static)
  endif()
endif()
