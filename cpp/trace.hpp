#pragma once
// lmnet traceroute-lite: classic UDP-probe traceroute (tracepath-style) —
// UDP datagrams with increasing IP_TTL plus ICMP answers on a raw socket.
// Pure C++, no vendoring. Linux-only, IPv4-only in v1: IPv6 destinations get
// a clean "not supported" error. Receiving ICMP needs CAP_NET_RAW (or root);
// without it trace_udp fails with "needs root or CAP_NET_RAW".

#include <cstdint>
#include <string>
#include <vector>

namespace lmnet {

struct Hop {
  int64_t ttl = 0;          // probe TTL for this hop (1-based)
  std::string from;         // responding host IP, "" on timeout/star
  double rtt_ms = -1;       // < 0 when no reply was seen this hop
  bool reached = false;     // destination answered (ICMP port unreachable)
};

struct TraceResult {
  std::string dest_ip;      // resolved destination, "" when resolution failed
  std::string error;        // resolution/socket failure; hops empty then
  std::vector<Hop> hops;
};

// Resolve `host` (IPv4 first; an IPv6-only name fails with "IPv6 ... not
// supported") and run a UDP/ICMP traceroute: for ttl = 1..max_ttl send one
// UDP datagram to port 33434+ttl with IP_TTL set, then listen on a raw ICMP
// socket for a time-exceeded (router) or port-unreachable (destination,
// reached) reply, timing out per hop after `timeout_ms`. A star hop
// (from="", rtt_ms<0) records a silent hop. The whole run is bounded by an
// overall deadline of max_ttl*timeout_ms + slack so it can never hang.
// One probe per TTL; stops on reach or after max_hops hops.
TraceResult trace_udp(const std::string &host, int64_t max_ttl,
                      int64_t timeout_ms, int64_t max_hops);

} // namespace lmnet
