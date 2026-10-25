#pragma once
// lmnet DNS message client (dig-lite): builds RFC 1035 queries, speaks UDP to
// a resolver, and renders the answer section as text. Pure C++, no vendoring.

#include <cstdint>
#include <string>
#include <vector>

namespace lmnet {

struct DnsAnswer {
  std::string name;
  std::string type;
  int64_t ttl = 0;
  std::string data;
};

struct DnsResult {
  std::string rcode;                 // NOERROR, FORMERR, SERVFAIL, NXDOMAIN, ...
  std::vector<DnsAnswer> answers;    // answer section only
  std::string error;                 // transport/parse failure; rcode unset then
};

// True when `type` (any case) is a query type the client supports.
bool dns_type_known(const std::string &type);

// Send a standard query (rd=1) for `name`/`type` to `server` ("host" or
// "host:port"; empty = first nameserver from /etc/resolv.conf) over connected
// UDP with a 3 s timeout. Supported types: A AAAA MX TXT NS SOA CNAME PTR.
// A nonzero rcode is reported in the result, not in error; only transport and
// parse failures (including a truncated response) set error.
DnsResult dns_query(const std::string &name, const std::string &type,
                    const std::string &server);

} // namespace lmnet
