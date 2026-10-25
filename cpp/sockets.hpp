#pragma once
// lmnet socket-table introspection: the netstat/lsof -i view from /proc.
// Pure C++, no vendored code. See net.hpp for the shared lmnet wrapper rules.

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

// Parse /proc/net/{tcp,tcp6,udp,udp6,unix} and attribute sockets to
// processes by scanning /proc/<pid>/fd for the socket inode. proto_filter
// ("tcp", "udp", "unix", "" for all) restricts the table; when only_listen
// is set only LISTEN tcp/udp sockets are returned. error is set when a
// required table cannot be read at all.
std::vector<Socket> socket_table(const std::string &proto_filter,
                                 bool only_listen, std::string &error);

} // namespace lmnet
