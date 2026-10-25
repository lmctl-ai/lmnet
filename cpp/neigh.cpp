#include "neigh.hpp"

#include <arpa/inet.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace lmnet {
namespace {

struct IdName {
  uint32_t id;
  const char *name;
};

// NUD_* neighbor states (linux/neighbour.h carries the full set).
constexpr IdName kStates[] = {
    {NUD_NONE, "none"},
    {NUD_INCOMPLETE, "incomplete"},
    {NUD_REACHABLE, "reachable"},
    {NUD_STALE, "stale"},
    {NUD_DELAY, "delay"},
    {NUD_PROBE, "probe"},
    {NUD_FAILED, "failed"},
    {NUD_NOARP, "noarp"},
    {NUD_PERMANENT, "permanent"},
};

std::string id_text(const IdName *table, size_t n, uint32_t id) {
  for (size_t i = 0; i < n; ++i)
    if (table[i].id == id) return table[i].name;
  return std::to_string(id);
}

// Render an NDA_LLADDR payload as colon-separated hex bytes; "" when empty.
std::string lladdr_text(const rtattr *rta) {
  const auto *bytes = static_cast<const unsigned char *>(RTA_DATA(rta));
  const size_t len = RTA_PAYLOAD(rta);
  std::string out;
  for (size_t i = 0; i < len; ++i) {
    if (i) out += ':';
    char byte[4];
    std::snprintf(byte, sizeof byte, "%02x", bytes[i]);
    out += byte;
  }
  return out;
}

Neighbor parse_neigh(const nlmsghdr *nlh) {
  const auto *ndm = static_cast<const ndmsg *>(NLMSG_DATA(nlh));
  Neighbor neigh;
  neigh.family = ndm->ndm_family == AF_INET    ? "ipv4"
                 : ndm->ndm_family == AF_INET6 ? "ipv6"
                                               : std::to_string(ndm->ndm_family);
  neigh.state =
      id_text(kStates, sizeof kStates / sizeof kStates[0], ndm->ndm_state);
  neigh.router = (ndm->ndm_flags & NTF_ROUTER) != 0;
  neigh.proxy = (ndm->ndm_flags & NTF_PROXY) != 0;

  int attr_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(ndmsg));
  uint32_t ifindex = ndm->ndm_ifindex;
  for (const rtattr *rta = RTM_RTA(ndm); RTA_OK(rta, attr_len);
       rta = RTA_NEXT(rta, attr_len)) {
    switch (rta->rta_type) {
    case NDA_DST: {
      char buf[INET6_ADDRSTRLEN] = {};
      const size_t want = ndm->ndm_family == AF_INET    ? 4
                          : ndm->ndm_family == AF_INET6 ? 16
                                                        : 0;
      if (want && RTA_PAYLOAD(rta) >= want &&
          inet_ntop(ndm->ndm_family, RTA_DATA(rta), buf, sizeof buf))
        neigh.ip = buf;
      break;
    }
    case NDA_LLADDR:
      neigh.mac = lladdr_text(rta);
      break;
    case NDA_IFINDEX:
      // Regular entries carry the index in ndm_ifindex; only cross-netns
      // entries (NDA_LINK_NETNSID) need the attribute override.
      if (RTA_PAYLOAD(rta) >= 4)
        ifindex = *static_cast<uint32_t *>(RTA_DATA(rta));
      break;
    default: break;
    }
  }
  char ifname[IFNAMSIZ] = {};
  if (ifindex != 0 && if_indextoname(ifindex, ifname))
    neigh.dev = ifname;
  return neigh;
}

} // namespace

std::vector<Neighbor> neighbors(std::string &error) {
  error.clear();
  std::vector<Neighbor> out;

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

  // Dump request: AF_UNSPEC covers IPv4 ARP + IPv6 NDP, like `ip neigh show`.
  struct {
    nlmsghdr nlh;
    ndmsg ndm;
  } request{};
  request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(ndmsg));
  request.nlh.nlmsg_type = RTM_GETNEIGH;
  request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  request.nlh.nlmsg_seq = 1;
  request.ndm.ndm_family = AF_UNSPEC;
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
      if (nlh->nlmsg_type != RTM_NEWNEIGH)
        continue;
      out.push_back(parse_neigh(nlh));
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
