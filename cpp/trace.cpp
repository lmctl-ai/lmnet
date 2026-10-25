#include "trace.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <string>
#include <vector>

namespace lmnet {
namespace {

using Clock = std::chrono::steady_clock;

std::string gai_text(int rc, const char *host) {
  const char *text = gai_strerror(rc);
  return text ? std::string(text) : std::string("resolver error for ") + host;
}

// Match one inbound ICMP packet against the probe: the embedded original
// IPv4 header must carry our destination (and, for port-unreachable, our
// probe port). Returns 0 when unrelated, else the ICMP type (11 or 3).
int probe_match(const uint8_t *buf, ssize_t got, in_addr target,
                uint16_t probe_port) {
  if (got < static_cast<ssize_t>(sizeof(iphdr)))
    return 0;
  const auto *ip = reinterpret_cast<const iphdr *>(buf);
  const size_t ihl = static_cast<size_t>(ip->ihl) * 4;
  if (got < static_cast<ssize_t>(ihl + sizeof(icmphdr)))
    return 0;
  const auto *icmp = reinterpret_cast<const icmphdr *>(buf + ihl);
  if (icmp->type != ICMP_TIME_EXCEEDED && icmp->type != ICMP_DEST_UNREACH)
    return 0;
  if (icmp->type == ICMP_DEST_UNREACH && icmp->code != ICMP_PORT_UNREACH)
    return 0;

  // Embedded original datagram after the ICMP header.
  const uint8_t *orig = buf + ihl + sizeof(icmphdr);
  const ssize_t left = got - static_cast<ssize_t>(ihl + sizeof(icmphdr));
  if (left < static_cast<ssize_t>(sizeof(iphdr)))
    return 0;
  const auto *oip = reinterpret_cast<const iphdr *>(orig);
  const size_t oihl = static_cast<size_t>(oip->ihl) * 4;
  if (oip->protocol != IPPROTO_UDP || oip->daddr != target.s_addr)
    return 0;
  if (icmp->type == ICMP_DEST_UNREACH) {
    if (left < static_cast<ssize_t>(oihl + 4))
      return 0;
    uint16_t dport = 0;
    std::memcpy(&dport, orig + oihl + 2, sizeof dport);
    if (ntohs(dport) != probe_port)
      return 0;
  }
  return icmp->type;
}

void drain(int fd) {
  uint8_t buf[2048];
  for (;;) {
    const ssize_t got = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
    if (got < 0 && errno == EINTR) continue;
    if (got <= 0) break;
  }
}

} // namespace

TraceResult trace_udp(const std::string &host, int64_t max_ttl,
                      int64_t timeout_ms, int64_t max_hops) {
  TraceResult result;
  if (max_ttl < 1) max_ttl = 1;
  if (max_ttl > 255) max_ttl = 255;
  if (timeout_ms < 1) timeout_ms = 1;
  if (timeout_ms > 60000) timeout_ms = 60000;
  if (max_hops < 1) max_hops = 1;
  if (max_hops > max_ttl) max_hops = max_ttl;

  // Resolve: IPv4 first, IPv6 only to produce a clean "not supported" error.
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  addrinfo *res = nullptr;
  int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
  if (rc != 0 || !res) {
    hints.ai_family = AF_INET6;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0 && res) {
      result.error = "IPv6-only destinations are not supported "
                     "(traceroute-lite is IPv4-only)";
      freeaddrinfo(res);
      return result;
    }
    result.error = gai_text(rc, host.c_str());
    return result;
  }
  sockaddr_in dest = *reinterpret_cast<sockaddr_in *>(res->ai_addr);
  freeaddrinfo(res);
  {
    char text[INET_ADDRSTRLEN] = {};
    if (!inet_ntop(AF_INET, &dest.sin_addr, text, sizeof text)) {
      result.error = std::strerror(errno);
      return result;
    }
    result.dest_ip = text;
  }

  const int icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (icmp_fd < 0) {
    if (errno == EACCES || errno == EPERM)
      result.error = "needs root or CAP_NET_RAW: ";
    else
      result.error = "raw socket: ";
    result.error += std::strerror(errno);
    return result;
  }
  {
    const int flags = fcntl(icmp_fd, F_GETFL, 0);
    if (flags >= 0) fcntl(icmp_fd, F_SETFL, flags | O_NONBLOCK);
  }
  const int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_fd < 0) {
    result.error = std::string("udp socket: ") + std::strerror(errno);
    close(icmp_fd);
    return result;
  }

  const Clock::time_point overall_deadline =
      Clock::now() +
      std::chrono::milliseconds(max_ttl * timeout_ms + 2000);  // slack

  const uint8_t payload = 0;
  for (int64_t ttl = 1; ttl <= max_ttl &&
                        static_cast<int64_t>(result.hops.size()) < max_hops;
       ++ttl) {
    if (Clock::now() >= overall_deadline) break;

    Hop hop;
    hop.ttl = ttl;
    const uint16_t port = static_cast<uint16_t>(33434 + ttl);

    const int ttl_opt = static_cast<int>(ttl);
    if (setsockopt(udp_fd, IPPROTO_IP, IP_TTL, &ttl_opt, sizeof ttl_opt) !=
        0) {
      result.error = std::string("IP_TTL: ") + std::strerror(errno);
      break;
    }
    drain(icmp_fd);
    dest.sin_port = htons(port);
    const Clock::time_point sent = Clock::now();
    if (sendto(udp_fd, &payload, sizeof payload, 0,
               reinterpret_cast<sockaddr *>(&dest), sizeof dest) < 0) {
      result.error = std::string("send: ") + std::strerror(errno);
      break;
    }

    const Clock::time_point hop_deadline =
        sent + std::chrono::milliseconds(timeout_ms);
    for (;;) {
      const auto now = Clock::now();
      const auto sooner = hop_deadline < overall_deadline ? hop_deadline
                                                          : overall_deadline;
      const int wait_ms = now >= sooner
                              ? 0
                              : static_cast<int>(std::chrono::duration_cast<
                                     std::chrono::milliseconds>(sooner - now)
                                     .count());
      pollfd pfd{icmp_fd, POLLIN, 0};
      const int ready = poll(&pfd, 1, wait_ms);
      if (ready < 0) {
        if (errno == EINTR) continue;
        result.error = std::string("poll: ") + std::strerror(errno);
        break;
      }
      if (ready == 0) break;  // per-hop timeout: star
      uint8_t buf[2048];
      const ssize_t got = recv(icmp_fd, buf, sizeof buf, 0);
      if (got < 0) {
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
        result.error = std::string("recv: ") + std::strerror(errno);
        break;
      }
      char from_text[INET_ADDRSTRLEN] = {};
      const auto *ip = reinterpret_cast<const iphdr *>(buf);
      if (got < static_cast<ssize_t>(sizeof(iphdr)) ||
          !inet_ntop(AF_INET, &ip->saddr, from_text, sizeof from_text))
        continue;
      const int kind = probe_match(buf, got, dest.sin_addr, port);
      if (!kind) continue;  // unrelated ICMP: ignore
      hop.from = from_text;
      hop.rtt_ms = std::chrono::duration<double, std::milli>(Clock::now() - sent)
                       .count();
      hop.reached = kind == ICMP_DEST_UNREACH;
      break;
    }
    result.hops.push_back(std::move(hop));
    if (!result.error.empty()) break;
    if (result.hops.back().reached) break;
  }

  close(udp_fd);
  close(icmp_fd);
  if (!result.error.empty())
    result.hops.clear();
  return result;
}

} // namespace lmnet
