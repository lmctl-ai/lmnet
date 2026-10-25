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
set(LMNET_STD_SCHEMA "${CMAKE_CURRENT_SOURCE_DIR}/cpp/std/lmcode-std.schema.json")
set(LMNET_MERGE_HELPER "${CMAKE_CURRENT_SOURCE_DIR}/scripts/merge-std.py")

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

# ---- effective schema (host fragment merged with the lmcode std catalog) ----
set(SCHEMA_JSON "${CMAKE_CURRENT_SOURCE_DIR}/schema/lmnet.dsl.json")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${LMNET_HOST_SCHEMA}" "${LMNET_STD_SCHEMA}" "${LMNET_MERGE_HELPER}")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${LMNET_MERGE_HELPER}" "${LMNET_HOST_SCHEMA}" "${SCHEMA_JSON}" RESULT_VARIABLE LMNET_MERGE_RESULT ERROR_VARIABLE LMNET_MERGE_ERROR)
if(NOT LMNET_MERGE_RESULT EQUAL 0)
  message(FATAL_ERROR "failed to merge lmcode std schema: ${LMNET_MERGE_ERROR}")
endif()
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
  cpp/sockets.cpp
  ${IPUTILS_SOURCES}
  "${GENERATED_SCHEMA}"
)
add_dependencies(lmnet lmnet_schema)

# cpp/iputilsshim/ (our config.h stand-in) shadows upstream; otherwise the
# include layout mirrors the iputils build.
target_include_directories(lmnet PRIVATE
  cpp/iputilsshim
  cpp
  "${IPUTILS_ROOT}"
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
# iputils sources are third-party: silence their warnings, keep ours strict.
# meson force-includes git-version.h (-include); our shim dir supplies it.
set_source_files_properties(${IPUTILS_SOURCES} PROPERTIES
  COMPILE_OPTIONS "-w;-include;git-version.h"
)
target_compile_options(lmnet PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(lmnet PRIVATE LMNET_VERSION="${PROJECT_VERSION}")

# Static linking: no runtime dependency beyond the OS C library.
if((CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang") AND NOT APPLE)
  target_link_options(lmnet PRIVATE -static-libstdc++ -static-libgcc)
  if(LMNET_FULL_STATIC)
    target_link_options(lmnet PRIVATE -static)
  endif()
endif()
