# Embeds a JSON schema file as a constexpr byte array (schema_embedded.hpp).
# Called with -DINPUT=<json> -DOUTPUT=<hpp>.
file(READ "${INPUT}" _schema_hex HEX)
string(LENGTH "${_schema_hex}" _hex_len)
math(EXPR _byte_len "${_hex_len} / 2")
string(REGEX REPLACE "(..)" "0x\\1," _schema_bytes "${_schema_hex}")
string(REGEX REPLACE ",$" "" _schema_bytes "${_schema_bytes}")
file(WRITE "${OUTPUT}"
"// Generated from schema/lmnet.dsl.json by cmake/embed_schema.cmake. Do not edit.
#pragma once
namespace lmnet {
inline constexpr unsigned char embedded_schema[] = {${_schema_bytes}};
inline constexpr unsigned int embedded_schema_size = ${_byte_len};
}
")
