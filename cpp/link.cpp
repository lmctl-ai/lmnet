#include "link.hpp"

#include <linux/if_link.h>
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

// Render an IFLA_ADDRESS payload as colon-separated hex bytes; "" when empty.
std::string addr_text(const rtattr *rta) {
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

Link parse_link(const nlmsghdr *nlh) {
  const auto *ifi = static_cast<const ifinfomsg *>(NLMSG_DATA(nlh));
  Link link;
  link.index = ifi->ifi_index;
  link.up = (ifi->ifi_flags & IFF_UP) != 0;
  link.loopback = (ifi->ifi_flags & IFF_LOOPBACK) != 0;

  int attr_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(ifinfomsg));
  for (const rtattr *rta = IFLA_RTA(ifi); RTA_OK(rta, attr_len);
       rta = RTA_NEXT(rta, attr_len)) {
    switch (rta->rta_type) {
    case IFLA_IFNAME:
      link.name = static_cast<const char *>(RTA_DATA(rta));
      break;
    case IFLA_MTU:
      if (RTA_PAYLOAD(rta) >= 4)
        link.mtu = *static_cast<int *>(RTA_DATA(rta));
      break;
    case IFLA_ADDRESS:
      link.mac = addr_text(rta);
      break;
    case IFLA_TXQLEN:
      if (RTA_PAYLOAD(rta) >= 4)
        link.txqlen = *static_cast<unsigned int *>(RTA_DATA(rta));
      break;
    case IFLA_STATS64:
      if (RTA_PAYLOAD(rta) >= static_cast<int>(sizeof(rtnl_link_stats64))) {
        const auto *st = static_cast<const rtnl_link_stats64 *>(RTA_DATA(rta));
        link.rx_bytes = st->rx_bytes;
        link.rx_packets = st->rx_packets;
        link.rx_errors = st->rx_errors;
        link.rx_dropped = st->rx_dropped;
        link.tx_bytes = st->tx_bytes;
        link.tx_packets = st->tx_packets;
        link.tx_errors = st->tx_errors;
        link.tx_dropped = st->tx_dropped;
      }
      break;
    default: break;
    }
  }
  return link;
}

} // namespace

std::vector<Link> links(std::string &error) {
  error.clear();
  std::vector<Link> out;

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

  // Dump request: AF_UNSPEC covers every link device, like `ip link show`.
  struct {
    nlmsghdr nlh;
    ifinfomsg ifi;
  } request{};
  request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(ifinfomsg));
  request.nlh.nlmsg_type = RTM_GETLINK;
  request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  request.nlh.nlmsg_seq = 1;
  request.ifi.ifi_family = AF_UNSPEC;
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
        const auto *err = static_cast<const nlmsgerr *>(NLMSG_DATA(nlh));
        if (err->error != 0)
          error = std::strerror(-err->error);
        done = true;
        break;
      }
      if (nlh->nlmsg_type != RTM_NEWLINK)
        continue;
      out.push_back(parse_link(nlh));
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
