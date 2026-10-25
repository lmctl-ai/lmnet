#pragma once
// lmnet kernel networking counters (netstat -s/nstat-lite): dumps the
// kernel's protocol counters from /proc/net/snmp, /proc/net/netstat, and
// /proc/net/snmp6 and renders them as plain data. Pure C++ file parsing, no
// vendoring. Linux-only by definition (/proc/net). Unlike `link` (per-device
// RX/TX from rtnetlink), this covers the protocol-level counters that
// `netstat -s` and `nstat` print.

#include <cstdint>
#include <string>
#include <vector>

namespace lmnet {

struct Counter {
  std::string name;  // "Ip.InReceives" (snmp/netstat) or "Ip6InReceives" (snmp6)
  int64_t value = 0;
};

// Dump every kernel networking counter, sorted by name so output is
// deterministic. Sources that cannot be opened (e.g. /proc/net/snmp6 on
// kernels without IPv6) are skipped silently; error is set only when no
// source at all was readable, and the result is then empty.
std::vector<Counter> counters(std::string &error);

} // namespace lmnet
