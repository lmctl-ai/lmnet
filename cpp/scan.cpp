#include "scan.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <set>
#include <thread>

namespace lmnet {
namespace {

struct ServiceName {
  int port;
  const char *name;
};
constexpr ServiceName kServices[] = {
    {22, "ssh"},         {23, "telnet"},     {25, "smtp"},
    {53, "dns"},         {80, "http"},       {110, "pop3"},
    {143, "imap"},       {443, "https"},     {465, "smtps"},
    {587, "submission"}, {993, "imaps"},     {995, "pop3s"},
    {1433, "mssql"},     {3306, "mysql"},    {5432, "postgres"},
    {6379, "redis"},     {8080, "http-alt"}, {8443, "https-alt"},
    {27017, "mongod"},
};

constexpr int kDefaultPorts[] = {22, 53, 80, 110, 143, 443, 465, 587, 993,
                                 995, 3306, 5432, 6379, 8080, 8443};

bool all_digits(const std::string &s) {
  if (s.empty()) return false;
  for (char c : s)
    if (c < '0' || c > '9') return false;
  return true;
}

// Parse one decimal port; 5 digits max so atoi cannot overflow.
bool parse_port_number(const std::string &s, int *out, std::string &why) {
  if (s.empty() || s.size() > 5 || !all_digits(s)) {
    why = "bad port: " + (s.empty() ? std::string("(empty entry)") : s);
    return false;
  }
  const int v = std::atoi(s.c_str());
  if (v < 1 || v > 65535) {
    why = "port out of range 1-65535: " + s;
    return false;
  }
  *out = v;
  return true;
}

// Add one SPEC entry ("80" or "8000-8010") to the set.
bool add_spec_item(const std::string &item, std::set<int> &seen, std::string &why) {
  const size_t dash = item.find('-');
  if (dash == std::string::npos) {
    int port = 0;
    if (!parse_port_number(item, &port, why)) return false;
    seen.insert(port);
    return true;
  }
  int lo = 0, hi = 0;
  if (!parse_port_number(item.substr(0, dash), &lo, why) ||
      !parse_port_number(item.substr(dash + 1), &hi, why))
    return false;
  if (lo > hi) {
    why = "range is reversed: " + item;
    return false;
  }
  for (int p = lo; p <= hi; ++p) seen.insert(p);
  return true;
}

// Probe one address with a non-blocking connect to `port`:
// poll(POLLOUT, timeout) then getsockopt(SO_ERROR). Returns the verdict for
// the port, or "" when the socket itself could not be created.
std::string probe(const addrinfo *ai, int port, int timeout_ms) {
  const int fd = socket(ai->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                        ai->ai_protocol);
  if (fd < 0) return "";
  // getaddrinfo was called without a service, so stamp the port per probe.
  sockaddr_storage ss{};
  std::memcpy(&ss, ai->ai_addr, ai->ai_addrlen);
  if (ss.ss_family == AF_INET)
    reinterpret_cast<sockaddr_in *>(&ss)->sin_port =
        htons(static_cast<uint16_t>(port));
  else if (ss.ss_family == AF_INET6)
    reinterpret_cast<sockaddr_in6 *>(&ss)->sin6_port =
        htons(static_cast<uint16_t>(port));
  std::string state;
  if (connect(fd, reinterpret_cast<sockaddr *>(&ss), ai->ai_addrlen) == 0) {
    state = "open";
  } else {
    const int connect_errno = errno;
    if (connect_errno == EINPROGRESS || connect_errno == EWOULDBLOCK ||
        connect_errno == EALREADY) {
      pollfd pfd{fd, POLLOUT, 0};
      int rc;
      do {
        rc = poll(&pfd, 1, timeout_ms);
      } while (rc < 0 && errno == EINTR);
      if (rc <= 0) {
        state = "filtered";  // timeout, or the poll itself failed
      } else {
        int so_error = 0;
        socklen_t n = sizeof so_error;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &n) != 0)
          state = "filtered";
        else if (so_error == 0)
          state = "open";
        else if (so_error == ECONNREFUSED)
          state = "closed";
        else
          state = "filtered";
      }
    } else if (connect_errno == ECONNREFUSED) {
      state = "closed";
    } else {
      state = "filtered";
    }
  }
  close(fd);
  return state;
}

// Scan every port of `ports` against `ai` with up to `concurrency` workers.
// Writes each verdict into out[i]; ports[i].state is pre-set to "filtered"
// and only overwritten, so each entry keeps a verdict no matter what.
// Returns how many sockets could be created at all: 0 means this address is
// unusable (e.g. the family is unsupported) and the caller should move on.
int scan_address(const addrinfo *ai, const std::vector<int> &ports,
                 int timeout_ms, int concurrency,
                 std::vector<ScannedPort> *out) {
  std::atomic<size_t> next{0};
  std::atomic<int> sockets_made{0};
  const auto worker = [&] {
    for (;;) {
      const size_t i = next.fetch_add(1, std::memory_order_relaxed);
      if (i >= ports.size()) break;
      const std::string state = probe(ai, ports[i], timeout_ms);
      if (state.empty()) continue;  // socket() failed: keep "filtered"
      sockets_made.fetch_add(1, std::memory_order_relaxed);
      (*out)[i].state = state;
    }
  };
  const size_t workers =
      std::min<size_t>(static_cast<size_t>(std::max(1, concurrency)),
                       ports.size());
  std::vector<std::thread> threads;
  threads.reserve(workers - 1);
  for (size_t w = 1; w < workers; ++w) threads.emplace_back(worker);
  worker();
  for (auto &t : threads) t.join();
  return sockets_made.load();
}

} // namespace

std::string service_name(int port) {
  for (const auto &entry : kServices)
    if (entry.port == port) return entry.name;
  return "";
}

bool parse_ports(const std::string &spec, std::vector<int> &ports, std::string &why) {
  ports.clear();
  why.clear();
  if (spec.empty()) {
    ports.assign(std::begin(kDefaultPorts), std::end(kDefaultPorts));
    return true;
  }
  std::set<int> seen;
  size_t start = 0;
  while (true) {
    const size_t comma = spec.find(',', start);
    const std::string item =
        spec.substr(start, comma == std::string::npos ? std::string::npos
                                                      : comma - start);
    if (!add_spec_item(item, seen, why)) {
      ports.clear();
      return false;
    }
    if (comma == std::string::npos) break;
    start = comma + 1;
  }
  ports.assign(seen.begin(), seen.end());
  return true;
}

ScanResult scan(const std::string &host, const std::string &ports_spec,
                int timeout_ms, int concurrency, std::string &error) {
  error.clear();
  timeout_ms = std::max(100, std::min(30000, timeout_ms));
  concurrency = std::max(1, std::min(512, concurrency));
  ScanResult result;
  result.host = host;
  std::vector<int> port_nums;
  std::string why;
  if (!parse_ports(ports_spec, port_nums, why)) {
    error = "bad --ports spec: " + why;
    return result;
  }
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo *res = nullptr;
  const int gai = getaddrinfo(host.c_str(), nullptr, &hints, &res);
  if (gai != 0) {
    error = gai_strerror(gai);
    return result;
  }
  // A refused/reset peer must not be able to kill us mid-scan.
  std::signal(SIGPIPE, SIG_IGN);

  bool scanned = false;
  for (addrinfo *ai = res; ai && !scanned; ai = ai->ai_next) {
    result.ports.clear();
    result.ports.reserve(port_nums.size());
    for (int p : port_nums) {
      ScannedPort sp;
      sp.number = p;
      sp.state = "filtered";  // default verdict; workers overwrite it
      sp.service = service_name(p);
      result.ports.push_back(std::move(sp));
    }
    if (scan_address(ai, port_nums, timeout_ms, concurrency, &result.ports) == 0)
      continue;  // could not open a single socket here; try the next address
    char buf[INET6_ADDRSTRLEN] = {};
    void *src = nullptr;
    if (ai->ai_family == AF_INET)
      src = &reinterpret_cast<sockaddr_in *>(ai->ai_addr)->sin_addr;
    else if (ai->ai_family == AF_INET6)
      src = &reinterpret_cast<sockaddr_in6 *>(ai->ai_addr)->sin6_addr;
    result.resolved = src && inet_ntop(ai->ai_family, src, buf, sizeof buf)
                          ? buf
                          : host;
    scanned = true;
  }
  freeaddrinfo(res);
  if (!scanned) {
    error = "no usable address";
    result.ports.clear();
    return result;
  }
  for (const auto &p : result.ports) {
    if (p.state == "open")
      ++result.open;
    else if (p.state == "closed")
      ++result.closed;
    else
      ++result.filtered;
  }
  return result;
}

bool check_port(const std::string &host, int port, int timeout_ms) {
  if (port < 1 || port > 65535) return false;
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo *res = nullptr;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) return false;
  bool ok = false;
  for (addrinfo *ai = res; ai && !ok; ai = ai->ai_next)
    ok = probe(ai, port, timeout_ms) == "open";
  freeaddrinfo(res);
  return ok;
}

} // namespace lmnet
