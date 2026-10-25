#pragma once
// lmnet TCP connect port scanner (nmap-lite): non-blocking connect + poll +
// SO_ERROR per port, parallel over std::thread workers. Pure C++, no
// vendoring; POSIX sockets only, so IPv6 rides the same code path.

#include <cstdint>
#include <string>
#include <vector>

namespace lmnet {

struct ScannedPort {
  int number = 0;        // 1-65535
  std::string state;     // "open" (connected) | "closed" (ECONNREFUSED) |
                         // "filtered" (timeout or other error)
  std::string service;   // well-known name, "" when unknown
};

struct ScanResult {
  std::string host;                     // the input, verbatim
  std::string resolved;                 // the address the scan actually used
  std::vector<ScannedPort> ports;       // sorted ascending, one per port
  int open = 0;
  int closed = 0;
  int filtered = 0;
  std::string error;                    // resolution/usage failure; empty on success
};

// Parse SPEC: a comma list and/or ranges ("80", "22,53,80", "1-1024",
// "80,8000-8010"). An empty SPEC yields the built-in top-15. Returns false
// and fills `why` on a malformed entry or a port outside 1-65535. The output
// is deduped and sorted ascending.
bool parse_ports(const std::string &spec, std::vector<int> &ports, std::string &why);

// Well-known service name for a port ("" when unknown).
std::string service_name(int port);

// Scan `host` (hostname or IPv4/IPv6 literal, resolved with getaddrinfo
// AF_UNSPEC/SOCK_STREAM) over the ports in `ports_spec`, giving every port
// `timeout_ms` to connect, spread over up to `concurrency` parallel workers
// (timeout is clamped to 100..30000 ms, concurrency to 1..512). Addresses are
// tried in order until one yields a scan. On failure the result is empty and
// `error` carries the message (bad spec, resolution failure, no usable
// address); a refused/reset peer can never kill the caller (SIGPIPE is
// ignored on the scan path).
ScanResult scan(const std::string &host, const std::string &ports_spec,
                int timeout_ms, int concurrency, std::string &error);

// Single-port probe: true only when a TCP connect to `port` succeeds within
// `timeout_ms`. Every network condition (resolution failure, refusal,
// timeout) is false; never throws.
bool check_port(const std::string &host, int port, int timeout_ms);

} // namespace lmnet
