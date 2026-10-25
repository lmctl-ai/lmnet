#include "rule.hpp"

#include <arpa/inet.h>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
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

// FR_ACT_* (rtnetlink.h keeps only a subset; the reserved values are numeric
// for portability — some headers define FR_ACT_RES4 instead of RES1/RES2).
constexpr IdName kActions[] = {
    {FR_ACT_UNSPEC, "unspec"}, {FR_ACT_TO_TBL, "lookup"},
    {FR_ACT_GOTO, "goto"},     {FR_ACT_NOP, "nop"},
    {4, "res1"},               {5, "res2"},
    {6, "res3"},               {FR_ACT_BLACKHOLE, "blackhole"},
    {FR_ACT_UNREACHABLE, "unreachable"}, {FR_ACT_PROHIBIT, "prohibit"},
};

std::string action_text(unsigned int action) {
  for (const auto &entry : kActions)
    if (entry.id == action) return entry.name;
  return std::to_string(action);
}

std::string table_text(unsigned int table) {
  switch (table) {
  case RT_TABLE_LOCAL: return "local";
  case RT_TABLE_MAIN: return "main";
  case RT_TABLE_DEFAULT: return "default";
  case RT_TABLE_UNSPEC: return "unspec";
  default: return std::to_string(table);
  }
}

// Render an address attribute + prefix length as CIDR. Absent attribute means
// the rule matches all sources/destinations at the family default (""); a
// present attribute with a zero length is the explicit all-zeros prefix.
std::string cidr_text(const rtattr *rta, int prefix_len, int family) {
  if (!rta) return "";
  char buf[INET6_ADDRSTRLEN] = {};
  const size_t want = family == AF_INET6 ? 16 : 4;
  if (RTA_PAYLOAD(rta) >= want && inet_ntop(family, RTA_DATA(rta), buf, sizeof buf))
    return std::string(buf) + "/" + std::to_string(prefix_len);
  if (prefix_len == 0)
    return std::string(family == AF_INET6 ? "::" : "0.0.0.0") + "/0";
  return "";
}

Rule parse_rule(const nlmsghdr *nlh) {
  const auto *frh = static_cast<const fib_rule_hdr *>(NLMSG_DATA(nlh));
  Rule rule;

  // AF_UNSPEC rules render selectors as IPv4 (as iproute2 does).
  const int family = frh->family == AF_INET6 ? AF_INET6 : AF_INET;
  switch (frh->family) {
  case AF_INET: rule.family = "ipv4"; break;
  case AF_INET6: rule.family = "ipv6"; break;
  case AF_UNSPEC: rule.family = "any"; break;
  default: rule.family = std::to_string(frh->family); break;
  }
  rule.table = table_text(frh->table);
  rule.action = action_text(frh->action);

  const rtattr *src = nullptr, *dst = nullptr;
  const auto *attrs = reinterpret_cast<const rtattr *>(
      reinterpret_cast<const char *>(frh) + NLMSG_ALIGN(sizeof(fib_rule_hdr)));
  int attr_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(fib_rule_hdr));
  for (const rtattr *rta = attrs; RTA_OK(rta, attr_len);
       rta = RTA_NEXT(rta, attr_len)) {
    switch (rta->rta_type) {
    case FRA_PRIORITY:
      if (RTA_PAYLOAD(rta) >= 4)
        rule.pref = *static_cast<uint32_t *>(RTA_DATA(rta));
      break;
    case FRA_SRC: src = rta; break;
    case FRA_DST: dst = rta; break;
    case FRA_FWMARK: {
      if (RTA_PAYLOAD(rta) >= 4) {
        char mark[16];
        std::snprintf(mark, sizeof mark, "0x%x",
                      *static_cast<uint32_t *>(RTA_DATA(rta)));
        rule.fwmark = mark;
      }
      break;
    }
    case FRA_FWMASK: {
      if (RTA_PAYLOAD(rta) >= 4 &&
          *static_cast<uint32_t *>(RTA_DATA(rta)) != 0xffffffff) {
        char mask[16];
        std::snprintf(mask, sizeof mask, "/0x%x",
                      *static_cast<uint32_t *>(RTA_DATA(rta)));
        rule.fwmark += mask;
      }
      break;
    }
    case FRA_IIFNAME:
      rule.iif = static_cast<const char *>(RTA_DATA(rta));
      break;
    case FRA_OIFNAME:
      rule.oif = static_cast<const char *>(RTA_DATA(rta));
      break;
    case FRA_GOTO:
      if (RTA_PAYLOAD(rta) >= 4)
        rule.goto_target = *static_cast<uint32_t *>(RTA_DATA(rta));
      break;
    default: break;
    }
  }
  rule.from = cidr_text(src, frh->src_len, family);
  rule.to = cidr_text(dst, frh->dst_len, family);
  return rule;
}

} // namespace

std::vector<Rule> rules(std::string &error) {
  error.clear();
  std::vector<Rule> out;

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

  // Dump request: AF_UNSPEC + RT_TABLE_UNSPEC covers every rule, like
  // `ip rule show` (some kernels filter the dump otherwise).
  struct {
    nlmsghdr nlh;
    fib_rule_hdr frh;
  } request{};
  request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(fib_rule_hdr));
  request.nlh.nlmsg_type = RTM_GETRULE;
  request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  request.nlh.nlmsg_seq = 1;
  request.frh.family = AF_UNSPEC;
  request.frh.table = RT_TABLE_UNSPEC;
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
      if (nlh->nlmsg_type != RTM_NEWRULE)
        continue;
      out.push_back(parse_rule(nlh));
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
