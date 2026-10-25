#pragma once
// lmnet network introspection wrapper. Plain C++ interface so the CLI host
// (main.cpp) never touches the vendored tool headers.

#include <string>
#include <vector>

namespace lmnet {

struct Iface {
  std::string name;
  std::string addr;  // "192.0.2.1/24" style, empty when the iface has none
  int mtu = 0;
  bool up = false;
  bool loopback = false;
};

// Resolve a host the way nslookup does (getaddrinfo, AF_UNSPEC). Returns
// distinct numeric addresses ("192.0.2.1", "2001:db8::1"). error is set on
// resolution failure; the result is then empty.
std::vector<std::string> dns_lookup(const std::string &host, std::string &error);

// Enumerate network interfaces and their primary addresses (the "ip addr"
// view: getifaddrs + ifconfig-style ioctls). Loopback first is NOT
// guaranteed; callers sort if they care.
std::vector<Iface> interfaces(std::string &error);

} // namespace lmnet
