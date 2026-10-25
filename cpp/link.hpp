#pragma once
// lmnet link-layer introspection (ip -s link-lite): dumps every link device
// over rtnetlink with RX/TX counters and renders them as plain data. Pure C++,
// no vendoring. Linux-only by definition (NETLINK_ROUTE). Unlike ifaddrs
// (interfaces-with-addresses), this covers every link device, including ones
// with no addresses, and carries traffic counters.

#include <cstdint>
#include <string>
#include <vector>

namespace lmnet {

struct Link {
  std::string name; // IFLA_IFNAME
  int index = 0;    // ifinfomsg ifindex
  int mtu = 0;      // IFLA_MTU
  bool up = false;        // IFF_UP
  bool loopback = false;  // IFF_LOOPBACK
  std::string mac;  // IFLA_ADDRESS as colon-separated hex, "" when absent
  int txqlen = 0;   // IFLA_TXQLEN, 0 when absent
  // rtnl_link_stats64 counters, all 0 when IFLA_STATS64 is absent.
  int64_t rx_bytes = 0, rx_packets = 0, rx_errors = 0, rx_dropped = 0;
  int64_t tx_bytes = 0, tx_packets = 0, tx_errors = 0, tx_dropped = 0;
};

// Dump every link device (AF_UNSPEC, NLM_F_DUMP), like `ip -s link show`.
// error is set when the netlink exchange fails; the result is then empty.
std::vector<Link> links(std::string &error);

} // namespace lmnet
