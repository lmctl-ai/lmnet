#include "net.hpp"

#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <cstring>
#include <set>

namespace lmnet {

std::vector<std::string> dns_lookup(const std::string &host, std::string &error) {
  error.clear();
  std::vector<std::string> out;
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo *res = nullptr;
  const int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
  if (rc != 0) {
    error = gai_strerror(rc);
    return out;
  }
  std::set<std::string> seen;
  for (addrinfo *ai = res; ai; ai = ai->ai_next) {
    char buf[INET6_ADDRSTRLEN] = {};
    void *src = nullptr;
    if (ai->ai_family == AF_INET)
      src = &reinterpret_cast<sockaddr_in *>(ai->ai_addr)->sin_addr;
    else if (ai->ai_family == AF_INET6)
      src = &reinterpret_cast<sockaddr_in6 *>(ai->ai_addr)->sin6_addr;
    else
      continue;
    if (!inet_ntop(ai->ai_family, src, buf, sizeof buf))
      continue;
    if (seen.emplace(buf).second)
      out.emplace_back(buf);
  }
  freeaddrinfo(res);
  if (out.empty() && error.empty())
    error = "no addresses";
  return out;
}

std::vector<Iface> interfaces(std::string &error) {
  error.clear();
  std::vector<Iface> out;
  ifaddrs *ifap = nullptr;
  if (getifaddrs(&ifap) != 0) {
    error = std::strerror(errno);
    return out;
  }
  // One entry per (name, family) pair; keep the first address of each iface
  // and query flags/MTU once per name.
  std::set<std::string> done;
  const int fd = socket(AF_INET, SOCK_DGRAM, 0);
  for (ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_name)
      continue;
    const std::string name = ifa->ifa_name;
    if (!done.emplace(name).second)
      continue;
    Iface iface;
    iface.name = name;
    const unsigned flags = ifa->ifa_flags;
    iface.up = (flags & IFF_UP) != 0;
    iface.loopback = (flags & IFF_LOOPBACK) != 0;
    if (fd >= 0) {
      ifreq req{};
      std::strncpy(req.ifr_name, name.c_str(), IFNAMSIZ - 1);
      if (ioctl(fd, SIOCGIFMTU, &req) == 0)
        iface.mtu = req.ifr_mtu;
    }
    // primary address with prefix length, IPv4 or IPv6
    for (ifaddrs *a2 = ifap; a2; a2 = a2->ifa_next) {
      if (!a2->ifa_name || name != a2->ifa_name || !a2->ifa_addr)
        continue;
      char buf[INET6_ADDRSTRLEN] = {};
      void *src = nullptr;
      int family = a2->ifa_addr->sa_family;
      unsigned prefix = 0;
      if (family == AF_INET) {
        auto *sin = reinterpret_cast<sockaddr_in *>(a2->ifa_addr);
        auto *mask = reinterpret_cast<sockaddr_in *>(a2->ifa_netmask);
        if (!mask)
          continue;
        src = &sin->sin_addr;
        unsigned long m = ntohl(mask->sin_addr.s_addr);
        while (m & 0x80000000u) { ++prefix; m <<= 1; }
      } else if (family == AF_INET6) {
        auto *sin6 = reinterpret_cast<sockaddr_in6 *>(a2->ifa_addr);
        auto *mask = reinterpret_cast<sockaddr_in6 *>(a2->ifa_netmask);
        if (!mask)
          continue;
        src = &sin6->sin6_addr;
        for (int i = 0; i < 16 && mask->sin6_addr.s6_addr[i] == 0xff; ++i)
          prefix += 8;
      } else {
        continue;
      }
      if (!inet_ntop(family, src, buf, sizeof buf))
        continue;
      iface.addr = std::string(buf) + "/" + std::to_string(prefix);
      break;
    }
    out.push_back(std::move(iface));
  }
  if (fd >= 0)
    close(fd);
  freeifaddrs(ifap);
  return out;
}

} // namespace lmnet
