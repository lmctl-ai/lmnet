#include "route.hpp"

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>

namespace lmnet {
namespace {

struct IdName {
  uint32_t id;
  const char *name;
};

// RTPROT_* (rtnetlink.h keeps only a subset; the rest mirror iproute2).
constexpr IdName kProtos[] = {
    {RTPROT_REDIRECT, "redirect"}, {RTPROT_KERNEL, "kernel"},
    {RTPROT_BOOT, "boot"},         {RTPROT_STATIC, "static"},
    {6, "gated"},                  {RTPROT_RA, "ra"},
    {10, "mrt"},                   {11, "zebra"},
    {RTPROT_BIRD, "bird"},         {13, "dnrouted"},
    {14, "xorp"},                  {15, "ntk"},
    {RTPROT_DHCP, "dhcp"},         {17, "mrouted"},
    {18, "keepalived"},            {19, "babel"},
    {42, "bgp"},                   {186, "isis"},
    {187, "ospf"},                 {188, "rip"},
    {189, "eigrp"},
};

constexpr IdName kTables[] = {
    {RT_TABLE_COMPAT, "compat"},
    {RT_TABLE_DEFAULT, "default"},
    {RT_TABLE_MAIN, "main"},
    {RT_TABLE_LOCAL, "local"},
};

constexpr IdName kScopes[] = {
    {RT_SCOPE_UNIVERSE, "global"},
    {RT_SCOPE_SITE, "site"},
    {RT_SCOPE_LINK, "link"},
    {RT_SCOPE_HOST, "host"},
    {RT_SCOPE_NOWHERE, "nowhere"},
};

std::string id_text(const IdName *table, size_t n, uint32_t id) {
  for (size_t i = 0; i < n; ++i)
    if (table[i].id == id) return table[i].name;
  return std::to_string(id);
}

// Render an RTA address attribute as text; "" on truncation/unknown family.
std::string attr_addr(const rtattr *rta, int family) {
  char buf[INET6_ADDRSTRLEN] = {};
  if (family == AF_INET && RTA_PAYLOAD(rta) >= 4)
    return inet_ntop(AF_INET, RTA_DATA(rta), buf, sizeof buf) ? buf : "";
  if (family == AF_INET6 && RTA_PAYLOAD(rta) >= 16)
    return inet_ntop(AF_INET6, RTA_DATA(rta), buf, sizeof buf) ? buf : "";
  return "";
}

Route parse_route(const nlmsghdr *nlh, std::string *parse_error) {
  const auto *rtm = static_cast<const rtmsg *>(NLMSG_DATA(nlh));
  Route route;

  // Destination: RTA_DST + rtm_dst_len, "default" when the prefix is empty.
  const rtattr *dst = nullptr;
  uint32_t table = rtm->rtm_table;
  int attr_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(rtmsg));
  for (const rtattr *rta = RTM_RTA(rtm); RTA_OK(rta, attr_len);
       rta = RTA_NEXT(rta, attr_len)) {
    switch (rta->rta_type) {
    case RTA_DST: dst = rta; break;
    case RTA_GATEWAY: route.via = attr_addr(rta, rtm->rtm_family); break;
    case RTA_PREFSRC: route.prefsrc = attr_addr(rta, rtm->rtm_family); break;
    case RTA_OIF: {
      char ifname[IFNAMSIZ] = {};
      if (RTA_PAYLOAD(rta) >= 4 &&
          if_indextoname(*static_cast<uint32_t *>(RTA_DATA(rta)), ifname))
        route.dev = ifname;
      break;
    }
    case RTA_PRIORITY:
      if (RTA_PAYLOAD(rta) >= 4)
        route.metric = static_cast<int32_t>(*static_cast<uint32_t *>(RTA_DATA(rta)));
      break;
    case RTA_TABLE:
      if (RTA_PAYLOAD(rta) >= 4)
        table = *static_cast<uint32_t *>(RTA_DATA(rta));
      break;
    default: break;
    }
  }
  route.table = id_text(kTables, sizeof kTables / sizeof kTables[0], table);
  route.proto = id_text(kProtos, sizeof kProtos / sizeof kProtos[0],
                        rtm->rtm_protocol);

  if (rtm->rtm_family == AF_INET || rtm->rtm_family == AF_INET6) {
    const size_t want = rtm->rtm_family == AF_INET ? 4 : 16;
    if (dst && RTA_PAYLOAD(dst) >= want) {
      char buf[INET6_ADDRSTRLEN] = {};
      if (inet_ntop(rtm->rtm_family, RTA_DATA(dst), buf, sizeof buf))
        route.dest = std::string(buf) + "/" + std::to_string(rtm->rtm_dst_len);
    } else if (!dst && rtm->rtm_dst_len == 0) {
      route.dest = "default";
    }
  }
  if (route.dest.empty()) {
    *parse_error = "route with unsupported family " +
                   std::to_string(rtm->rtm_family);
    return route;
  }
  route.scope = id_text(kScopes, sizeof kScopes / sizeof kScopes[0],
                        rtm->rtm_scope);
  return route;
}

} // namespace

std::vector<Route> routes(std::string &error) {
  error.clear();
  std::vector<Route> out;

  const int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd < 0) {
    error = std::strerror(errno);
    return out;
  }
  sockaddr_nl local{};
  local.nl_family = AF_NETLINK;
  if (bind(fd, reinterpret_cast<sockaddr *>(&local), sizeof local) != 0) {
    error = std::strerror(errno);
    close(fd);
    return out;
  }

  // Dump request: AF_UNSPEC covers IPv4 + IPv6 and every table, like
  // `ip route show table all`.
  struct {
    nlmsghdr nlh;
    rtmsg rtm;
  } request{};
  request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
  request.nlh.nlmsg_type = RTM_GETROUTE;
  request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  request.nlh.nlmsg_seq = 1;
  request.rtm.rtm_family = AF_UNSPEC;
  request.rtm.rtm_table = RT_TABLE_UNSPEC;
  if (send(fd, &request, request.nlh.nlmsg_len, 0) < 0) {
    error = std::string("send: ") + std::strerror(errno);
    close(fd);
    return out;
  }

  for (;;) {
    uint8_t buf[1 << 20];
    const ssize_t got = recv(fd, buf, sizeof buf, 0);
    if (got < 0) {
      if (errno == EINTR) continue;
      error = std::string("recv: ") + std::strerror(errno);
      break;
    }
    if (got == 0)
      break;  // kernel closed the socket mid-dump: treat as end of stream
    bool done = false;
    ssize_t msg_len = got;
    for (nlmsghdr *nlh = reinterpret_cast<nlmsghdr *>(buf); NLMSG_OK(nlh, msg_len);
         nlh = NLMSG_NEXT(nlh, msg_len)) {
      if (nlh->nlmsg_seq != 1 && nlh->nlmsg_seq != 0)
        continue;
      if (nlh->nlmsg_type == NLMSG_DONE) {
        done = true;
        break;
      }
      if (nlh->nlmsg_type == NLMSG_ERROR) {
        const auto *err = static_cast<nlmsgerr *>(NLMSG_DATA(nlh));
        if (err->error != 0)
          error = std::strerror(-err->error);
        done = true;
        break;
      }
      if (nlh->nlmsg_type != RTM_NEWROUTE)
        continue;
      std::string parse_error;
      Route route = parse_route(nlh, &parse_error);
      if (!parse_error.empty()) {
        error = parse_error;
        done = true;
        break;
      }
      out.push_back(std::move(route));
    }
    if (done || got < static_cast<ssize_t>(sizeof buf))
      break;
  }
  close(fd);
  if (!error.empty())
    out.clear();
  return out;
}

} // namespace lmnet
