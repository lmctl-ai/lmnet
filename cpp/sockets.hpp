#pragma once
// lmnet socket-table introspection: the netstat/lsof -i view from /proc.
// Pure C++, no vendored code. See net.hpp for the shared lmnet wrapper rules.

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace lmnet {

struct Socket {
  std::string proto;   // "tcp", "tcp6", "udp", "udp6", "unix"
  std::string local;   // "192.0.2.1:80" / "[2001:db8::1]:443" / path
  std::string remote;  // same shape; "" for unix and unconnected udp
  std::string state;   // "LISTEN", "ESTABLISHED", "TIME_WAIT", ...; "" for unix
  int64_t pid = 0;     // 0 when no owning process was found
  std::string process; // /proc/<pid>/comm when found
};

// ss -s-style aggregate over the socket table. Every count is int; per-family
// counts (tcp/tcp6/udp/udp6/unix) sum to total, and tcp_states holds one
// entry per kernel TCP state name that actually occurs (empty when no tcp
// sockets made the filter).
struct SocketSummary {
  int64_t total = 0;                        // all sockets matching proto_filter
  int64_t tcp = 0;                          // tcp sockets (v4)
  int64_t tcp6 = 0;                         // tcp sockets (v6)
  int64_t udp = 0;                          // udp sockets (v4)
  int64_t udp6 = 0;                         // udp sockets (v6)
  int64_t unix = 0;                         // unix sockets (named paths only)
  int64_t listening = 0;                    // sockets with state LISTEN
  std::map<std::string, int64_t> tcp_states; // kernel state name -> count
};

// Parse /proc/net/{tcp,tcp6,udp,udp6,unix} and attribute sockets to
// processes by scanning /proc/<pid>/fd for the socket inode. proto_filter
// ("tcp", "udp", "unix", "" for all) restricts the table; when only_listen
// is set only LISTEN tcp/udp sockets are returned. error is set when a
// required table cannot be read at all.
std::vector<Socket> socket_table(const std::string &proto_filter,
                                 bool only_listen, std::string &error);

// ss -s-style aggregate: builds on socket_table(proto_filter, false, error)
// and counts per family, per kernel tcp state, and LISTEN sockets. The same
// proto_filter values apply ("" for all); error is set exactly when
// socket_table fails.
SocketSummary socket_summary(const std::string &proto_filter, std::string &error);

} // namespace lmnet
