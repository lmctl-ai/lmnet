#pragma once
// lmnet neighbor-table introspection (ip neigh/arp-lite): dumps the kernel
// ARP/NDP tables over rtnetlink and renders them as plain data. Pure C++,
// no vendoring. Linux-only by definition (NETLINK_ROUTE).

#include <cstdint>
#include <string>
#include <vector>

namespace lmnet {

struct Neighbor {
  std::string ip;     // human form, IPv4 or IPv6
  std::string dev;    // interface name from ndm_ifindex (NDA_IFINDEX override)
  std::string state;  // NUD state lowercased, number string when unknown
  std::string mac;    // link-layer address, "" when NDA_LLADDR absent
  std::string family; // "ipv4"/"ipv6" from the AF, number fallback
  bool router = false; // NTF_ROUTER
  bool proxy = false;  // NTF_PROXY
};

// Dump the whole neighbor table (AF_UNSPEC: IPv4 ARP + IPv6 NDP), like
// `ip neigh show`. error is set when the netlink exchange fails; the result
// is then empty.
std::vector<Neighbor> neighbors(std::string &error);

} // namespace lmnet
