#pragma once
// lmnet routing-table introspection (ip route-lite): dumps the kernel
// forwarding tables over rtnetlink and renders them as plain data. Pure C++,
// no vendoring. Linux-only by definition (NETLINK_ROUTE).

#include <cstdint>
#include <string>
#include <vector>

namespace lmnet {

struct Route {
  std::string dest;    // "default" or CIDR "192.0.2.0/24"
  std::string via;     // gateway IP, "" when none
  std::string dev;     // output interface, "" when none (e.g. unreachable protos)
  std::string proto;   // "kernel", "boot", "static", "dhcp", number fallback
  std::string scope;   // "global"/"link"/"host"/"universe" or ""
  int64_t metric = 0;
  std::string table;   // "main", "local", "default", or a number
  std::string prefsrc; // preferred source, "" when none
};

// Dump all routing tables (AF_UNSPEC: IPv4 + IPv6, main + local + custom).
// Routes from non-main tables keep their table name. error is set when the
// netlink exchange fails; the result is then empty.
std::vector<Route> routes(std::string &error);

} // namespace lmnet
