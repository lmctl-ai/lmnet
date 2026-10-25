#pragma once
// lmnet policy-routing-rule introspection (ip rule-lite): dumps the kernel's
// rule list over rtnetlink and renders it as plain data. Pure C++, no
// vendoring. Linux-only by definition (NETLINK_ROUTE).

#include <cstdint>
#include <string>
#include <vector>

namespace lmnet {

struct Rule {
  int pref = 0;            // FRA_PRIORITY (0 when the kernel omits it)
  std::string family;      // "ipv4"/"ipv6"/"any" from frh_family
  std::string table;       // "main"/"local"/"default"/"unspec", else a number
  std::string action;      // "lookup"/"goto"/"blackhole"/... from frh_action
  std::string from;        // FRA_SRC + frh_src_len as CIDR, "" when absent
  std::string to;          // FRA_DST + frh_dst_len as CIDR, "" when absent
  std::string fwmark;      // "0xNN[/0xMM]", "" when FRA_FWMARK is absent
  std::string iif;         // FRA_IIFNAME, "" when absent
  std::string oif;         // FRA_OIFNAME, "" when absent
  int goto_target = -1;    // FRA_GOTO for goto rules, -1 when absent
};

// Dump every policy rule (AF_UNSPEC, NLM_F_DUMP), like `ip rule show`.
// error is set when the netlink exchange fails; the result is then empty.
std::vector<Rule> rules(std::string &error);

} // namespace lmnet
