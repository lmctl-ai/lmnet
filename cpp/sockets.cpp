#include "sockets.hpp"

#include <cctype>
#include <cstdint>
#include <dirent.h>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <unistd.h>

namespace lmnet {
namespace {

std::string read_file(const std::string &path) {
  std::ifstream in(path);
  if (!in) return "";
  std::ostringstream data;
  data << in.rdbuf();
  return data.str();
}

unsigned hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 0;
}

// "0100007F:0035" -> "127.0.0.1:53" (IPv4 addresses in /proc are
// little-endian hex: the displayed octets are reversed).
std::string format_endpoint4(const std::string &hex) {
  const auto colon = hex.find(':');
  if (colon == std::string::npos || colon != 8) return hex;
  unsigned char b[4];
  for (int i = 0; i < 4; ++i)
    b[i] = static_cast<unsigned char>(hexval(hex[i * 2]) * 16 + hexval(hex[i * 2 + 1]));
  const unsigned port = static_cast<unsigned>(
      hexval(hex[colon + 1]) * 4096 + hexval(hex[colon + 2]) * 256 +
      hexval(hex[colon + 3]) * 16 + hexval(hex[colon + 4]));
  std::ostringstream out;
  out << static_cast<int>(b[3]) << '.' << static_cast<int>(b[2]) << '.'
      << static_cast<int>(b[1]) << '.' << static_cast<int>(b[0]) << ':' << port;
  return out.str();
}

// "00000000000000000000000001000000:0016" -> "[::1]:22"
std::string format_endpoint6(const std::string &hex) {
  const auto colon = hex.find(':');
  if (colon == std::string::npos || colon != 32) return hex;
  const unsigned port = static_cast<unsigned>(
      hexval(hex[colon + 1]) * 4096 + hexval(hex[colon + 2]) * 256 +
      hexval(hex[colon + 3]) * 16 + hexval(hex[colon + 4]));
  // /proc shows each 32-bit word in host (little-endian) order, so reverse
  // the bytes within every 4-byte group to recover the real address.
  unsigned char b[16];
  for (int i = 0; i < 4; ++i)
    for (int j = 0; j < 4; ++j) {
      const int src = (i * 4 + (3 - j)) * 2;
      b[i * 4 + j] = static_cast<unsigned char>(hexval(hex[src]) * 16 + hexval(hex[src + 1]));
    }
  std::ostringstream addr;
  addr << std::hex;
  for (int i = 0; i < 16; i += 2) {
    if (i) addr << ':';
    // compress the longest zero run of 16-bit groups
    unsigned group = (b[i] << 8) | b[i + 1];
    addr << group;
  }
  // simple compression pass on the rendered string
  std::string s = addr.str();
  std::string best;
  for (const std::string &pat : {":0:0:0:0:0:0:0", ":0:0:0:0:0:0", ":0:0:0:0:0", ":0:0:0:0", ":0:0:0"}) {
    auto pos = s.find(pat);
    if (pos != std::string::npos) {
      s = s.substr(0, pos) + "::" + s.substr(pos + pat.size());
      break;
    }
  }
  std::ostringstream out;
  out << '[' << s << "]:" << port;
  return out.str();
}

const char *tcp_state(const std::string &hex) {
  static const char *states[] = {
    "UNKNOWN", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
    "TIME_WAIT", "UNCONN", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING", "NEW_SYN_RECV"
  };
  const unsigned v = static_cast<unsigned>(
      hexval(hex[0]) * 16 + (hex.size() > 1 ? hexval(hex[1]) : 0));
  return v < sizeof(states) / sizeof(states[0]) ? states[v] : "UNKNOWN";
}

// inode -> (pid, comm) by scanning /proc/<pid>/fd for "socket:[inode]" links.
std::map<std::string, std::pair<int64_t, std::string>> owners() {
  std::map<std::string, std::pair<int64_t, std::string>> out;
  DIR *proc = opendir("/proc");
  if (!proc) return out;
  dirent *de;
  while ((de = readdir(proc))) {
    const std::string pid_str = de->d_name;
    if (pid_str.empty() || !std::isdigit(static_cast<unsigned char>(pid_str[0])))
      continue;
    const std::string fd_dir = "/proc/" + pid_str + "/fd";
    DIR *fds = opendir(fd_dir.c_str());
    if (!fds) continue;
    std::string comm = read_file("/proc/" + pid_str + "/comm");
    if (!comm.empty() && comm.back() == '\n') comm.pop_back();
    dirent *fe;
    while ((fe = readdir(fds))) {
      char link[256] = {};
      const std::string target = fd_dir + "/" + fe->d_name;
      const ssize_t n = readlink(target.c_str(), link, sizeof link - 1);
      if (n <= 0) continue;
      link[n] = 0;
      const std::string text = link;
      const auto open = text.find("socket:[");
      if (open == std::string::npos) continue;
      const auto close = text.find(']', open);
      if (close == std::string::npos) continue;
      const std::string inode = text.substr(open + 8, close - open - 8);
      // first owner wins; sorting by pid is not required for a debug tool
      out.emplace(inode, std::pair<int64_t, std::string>{std::atoll(pid_str.c_str()), comm});
    }
    closedir(fds);
  }
  closedir(proc);
  return out;
}

void parse_inet_table(const std::string &path, const std::string &proto,
                      bool v6, bool is_tcp, const std::map<std::string, std::pair<int64_t, std::string>> &owner,
                      const std::string &proto_filter, bool only_listen,
                      std::vector<Socket> &out) {
  if (!proto_filter.empty() && proto_filter != proto &&
      !(proto_filter == "tcp" && proto == "tcp6") &&
      !(proto_filter == "udp" && proto == "udp6"))
    return;
  std::ifstream in(path);
  if (!in) return; // kernel without IPv6: tcp6/udp6 absent is normal
  std::string line;
  std::getline(in, line); // header
  while (std::getline(in, line)) {
    std::istringstream ls(line);
    std::string sl, local_hex, remote_hex, st, txrx, trtm, retr, uid, timeout, inode;
    if (!(ls >> sl >> local_hex >> remote_hex >> st >> txrx >> trtm >> retr >> uid >> timeout >> inode))
      continue;
    const std::string state = is_tcp ? tcp_state(st) : (st == "07" ? "UNCONN" : "");
    // tcp listens with LISTEN; udp "listeners" are the UNCONN rows.
    if (only_listen && (is_tcp ? state != "LISTEN" : state != "UNCONN"))
      continue;
    Socket s;
    s.proto = proto;
    s.local = v6 ? format_endpoint6(local_hex) : format_endpoint4(local_hex);
    s.remote = v6 ? format_endpoint6(remote_hex) : format_endpoint4(remote_hex);
    s.state = state;
    if (inode != "0") {
      const auto it = owner.find(inode);
      if (it != owner.end()) {
        s.pid = it->second.first;
        s.process = it->second.second;
      }
    }
    out.push_back(std::move(s));
  }
}

void parse_unix_table(const std::map<std::string, std::pair<int64_t, std::string>> &owner,
                      const std::string &proto_filter,
                      std::vector<Socket> &out) {
  if (!proto_filter.empty() && proto_filter != "unix")
    return;
  std::ifstream in("/proc/net/unix");
  if (!in) return;
  std::string line;
  std::getline(in, line); // header
  while (std::getline(in, line)) {
    std::istringstream ls(line);
    std::string num, ref, proto_hex, flags, st, inode, type, path;
    if (!(ls >> num >> ref >> proto_hex >> flags >> st >> inode >> type))
      continue;
    if (!std::getline(ls, path)) path = "";
    while (!path.empty() && path.front() == ' ') path.erase(path.begin());
    if (path.empty())
      continue; // unnamed sockets: nothing meaningful to show in a debug view
    Socket s;
    s.proto = "unix";
    s.local = path;
    s.state = "";
    if (inode != "0") {
      const auto it = owner.find(inode);
      if (it != owner.end()) {
        s.pid = it->second.first;
        s.process = it->second.second;
      }
    }
    out.push_back(std::move(s));
  }
}

} // namespace

std::vector<Socket> socket_table(const std::string &proto_filter,
                                 bool only_listen, std::string &error) {
  error.clear();
  std::vector<Socket> out;
  if (!proto_filter.empty() && proto_filter != "tcp" && proto_filter != "udp" &&
      proto_filter != "unix") {
    error = "unknown protocol filter: " + proto_filter;
    return out;
  }
  std::ifstream probe("/proc/net/tcp");
  if (!probe) {
    error = "cannot read /proc/net/tcp (not a Linux host?)";
    return out;
  }
  probe.close();
  const auto owner = owners();
  parse_inet_table("/proc/net/tcp", "tcp", false, true, owner, proto_filter, only_listen, out);
  parse_inet_table("/proc/net/tcp6", "tcp6", true, true, owner, proto_filter, only_listen, out);
  parse_inet_table("/proc/net/udp", "udp", false, false, owner, proto_filter, only_listen, out);
  parse_inet_table("/proc/net/udp6", "udp6", true, false, owner, proto_filter, only_listen, out);
  parse_unix_table(owner, proto_filter, out);
  return out;
}

SocketSummary socket_summary(const std::string &proto_filter, std::string &error) {
  error.clear();
  SocketSummary summary;
  const auto table = socket_table(proto_filter, false, error);
  if (!error.empty())
    return summary;
  summary.total = static_cast<int64_t>(table.size());
  for (const auto &sock : table) {
    if (sock.proto == "tcp") ++summary.tcp;
    else if (sock.proto == "tcp6") ++summary.tcp6;
    else if (sock.proto == "udp") ++summary.udp;
    else if (sock.proto == "udp6") ++summary.udp6;
    else if (sock.proto == "unix") ++summary.unix;
    if (sock.state == "LISTEN") ++summary.listening;
    if (sock.proto == "tcp" || sock.proto == "tcp6")
      ++summary.tcp_states[sock.state];
  }
  return summary;
}

} // namespace lmnet
