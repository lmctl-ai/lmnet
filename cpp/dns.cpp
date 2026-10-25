#include "dns.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <random>
#include <sys/time.h>

namespace lmnet {
namespace {

constexpr uint16_t kTypeA = 1, kTypeNs = 2, kTypeCname = 5, kTypeSoa = 6,
                   kTypePtr = 12, kTypeMx = 15, kTypeTxt = 16, kTypeAaaa = 28;
constexpr uint16_t kClassIn = 1;

struct TypeName {
  const char *name;
  uint16_t code;
};
constexpr TypeName kTypes[] = {{"A", kTypeA},     {"NS", kTypeNs},
                               {"CNAME", kTypeCname}, {"SOA", kTypeSoa},
                               {"PTR", kTypePtr}, {"MX", kTypeMx},
                               {"TXT", kTypeTxt}, {"AAAA", kTypeAaaa}};

const TypeName *find_type(const std::string &type) {
  for (const auto &t : kTypes) {
    std::string up = t.name;
    if (type.size() == up.size()) {
      bool same = true;
      for (size_t i = 0; i < type.size(); ++i)
        same = same && std::toupper(static_cast<unsigned char>(type[i])) ==
                           static_cast<unsigned char>(up[i]);
      if (same) return &t;
    }
  }
  return nullptr;
}

std::string type_text(uint16_t code) {
  for (const auto &t : kTypes)
    if (t.code == code) return t.name;
  return "TYPE" + std::to_string(code);
}

const char *rcode_text(int rcode) {
  switch (rcode) {
  case 0: return "NOERROR";
  case 1: return "FORMERR";
  case 2: return "SERVFAIL";
  case 3: return "NXDOMAIN";
  case 4: return "NOTIMP";
  case 5: return "REFUSED";
  default: return nullptr;
  }
}

// ---- wire helpers ----

uint16_t get_u16(const uint8_t *p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t get_u32(const uint8_t *p) {
  return (static_cast<uint32_t>(get_u16(p)) << 16) | get_u16(p + 2);
}

// Decompress a (possibly compressed) domain name starting at *off. Output
// keeps the trailing root dot ("example.com."). Returns false on malformed
// input.
bool read_name(const uint8_t *msg, size_t len, size_t *off, std::string *out) {
  size_t pos = *off;
  size_t end = 0;  // position after the name when a pointer was followed
  std::string name;
  for (int jumps = 0;;) {
    if (pos >= len) return false;
    const uint8_t label = msg[pos];
    if ((label & 0xc0) == 0xc0) {
      if (pos + 1 >= len) return false;
      if (!end) end = pos + 2;
      if (++jumps > 16) return false;  // compression loop guard
      pos = ((static_cast<size_t>(label & 0x3f)) << 8) | msg[pos + 1];
      continue;
    }
    if ((label & 0xc0) != 0) return false;
    ++pos;
    if (label == 0) break;
    if (label > 63 || pos + label > len) return false;
    if (!name.empty()) name += '.';
    name.append(reinterpret_cast<const char *>(msg + pos), label);
    pos += label;
  }
  *off = end ? end : pos;
  *out = name + ".";
  return true;
}

std::string hex_bytes(const uint8_t *p, size_t n) {
  std::string out;
  out.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) {
    char buf[3];
    std::snprintf(buf, sizeof buf, "%02x", p[i]);
    out += buf;
  }
  return out;
}

// ---- query construction ----

bool encode_name(const std::string &name, std::string *wire) {
  wire->clear();
  size_t start = 0;
  while (start <= name.size()) {
    const size_t dot = name.find('.', start);
    const size_t end = dot == std::string::npos ? name.size() : dot;
    const size_t label = end - start;
    if (label > 63) return false;
    wire->push_back(static_cast<char>(label));
    wire->append(name, start, label);
    if (dot == std::string::npos) break;
    start = dot + 1;
    if (start == name.size()) break;  // trailing dot: root already encoded
  }
  wire->push_back('\0');
  return wire->size() <= 255;
}

// ---- server resolution ----

// Split "host", "host:port" or "[v6]:port" into host/port (default "53").
bool split_server(const std::string &server, std::string *host, std::string *port) {
  *host = server;
  *port = "53";
  if (server.empty()) return false;
  if (server.front() == '[') {
    const size_t close = server.find(']');
    if (close == std::string::npos) return false;
    *host = server.substr(1, close - 1);
    if (close + 1 < server.size()) {
      if (server[close + 1] != ':') return false;
      *port = server.substr(close + 2);
    }
    return !port->empty();
  }
  const size_t first = server.find(':');
  if (first != std::string::npos && first == server.rfind(':') &&
      first + 1 < server.size()) {
    *host = server.substr(0, first);
    *port = server.substr(first + 1);
  }
  return !host->empty() && !port->empty();
}

std::string default_nameserver() {
  FILE *f = std::fopen("/etc/resolv.conf", "r");
  if (!f) return "";
  char line[256];
  std::string server;
  while (std::fgets(line, sizeof line, f)) {
    std::string s = line;
    const size_t begin = s.find_first_not_of(" \t");
    if (begin == std::string::npos || s.compare(begin, 10, "nameserver") != 0)
      continue;
    const size_t value = s.find_first_not_of(" \t", begin + 10);
    if (value == std::string::npos) continue;
    const size_t end = s.find_first_of(" \t\r\n", value);
    server = s.substr(value, end == std::string::npos ? std::string::npos
                                                      : end - value);
    break;
  }
  std::fclose(f);
  return server;
}

std::string display_server(const std::string &host, const std::string &port) {
  return host.find(':') == std::string::npos ? host + ":" + port
                                             : "[" + host + "]:" + port;
}

// ---- answer rdata rendering ----

std::string render_rdata(const uint8_t *msg, size_t len, size_t rdata_off,
                         size_t rdlen, uint16_t type) {
  const uint8_t *rdata = msg + rdata_off;
  char buf[INET6_ADDRSTRLEN] = {};
  switch (type) {
  case kTypeA:
    if (rdlen == 4 && inet_ntop(AF_INET, rdata, buf, sizeof buf)) return buf;
    break;
  case kTypeAaaa:
    if (rdlen == 16 && inet_ntop(AF_INET6, rdata, buf, sizeof buf)) return buf;
    break;
  case kTypeNs:
  case kTypeCname:
  case kTypePtr: {
    std::string name;
    size_t off = rdata_off;
    if (read_name(msg, len, &off, &name)) return name;
    break;
  }
  case kTypeMx: {
    if (rdlen < 3) break;
    std::string name;
    size_t off = rdata_off + 2;
    if (read_name(msg, len, &off, &name))
      return std::to_string(get_u16(rdata)) + " " + name;
    break;
  }
  case kTypeSoa: {
    std::string mname, rname;
    size_t off = rdata_off;
    if (!read_name(msg, len, &off, &mname)) break;
    if (!read_name(msg, len, &off, &rname)) break;
    if (off + 20 > len) break;
    std::string out = mname + " " + rname;
    for (int i = 0; i < 5; ++i)
      out += " " + std::to_string(get_u32(msg + off + 4 * i));
    return out;
  }
  case kTypeTxt: {
    std::string out;
    size_t off = rdata_off;
    const size_t end = rdata_off + rdlen;
    while (off < end) {
      const size_t slen = msg[off++];
      if (off + slen > end) return out;  // malformed tail: keep what we have
      if (!out.empty()) out += ' ';
      out.append(reinterpret_cast<const char *>(msg + off), slen);
      off += slen;
    }
    return out;
  }
  default:
    break;
  }
  return "rdata:" + hex_bytes(rdata, rdlen);
}

} // namespace

bool dns_type_known(const std::string &type) { return find_type(type) != nullptr; }

DnsResult dns_query(const std::string &name, const std::string &type,
                    const std::string &server) {
  DnsResult result;
  const TypeName *qtype = find_type(type);
  if (!qtype) {
    result.error = "unsupported query type: " + type;
    return result;
  }
  std::string host, port;
  std::string server_arg = server.empty() ? default_nameserver() : server;
  if (server_arg.empty()) {
    result.error = "no server given and no nameserver found in /etc/resolv.conf";
    return result;
  }
  if (!split_server(server_arg, &host, &port)) {
    result.error = "bad server syntax (want host or host:port): " + server_arg;
    return result;
  }
  const std::string shown = display_server(host, port);

  // Connected UDP: ICMP port-unreachable surfaces as ECONNREFUSED on recv.
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  addrinfo *res = nullptr;
  const int gai = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
  if (gai != 0) {
    result.error = shown + ": " + gai_strerror(gai);
    return result;
  }
  int fd = -1;
  int saved_errno = 0;
  for (addrinfo *ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;
    timeval tv{3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
    saved_errno = errno;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) {
    result.error = shown + ": " +
                   std::strerror(saved_errno ? saved_errno : ECONNREFUSED);
    return result;
  }

  // Header: id, rd=1, one question.
  std::random_device rd;
  const uint16_t id = static_cast<uint16_t>(
      std::mt19937(rd() ^ static_cast<unsigned>(
                              std::chrono::steady_clock::now()
                                  .time_since_epoch()
                                  .count()))());
  std::string qname;
  if (!encode_name(name, &qname)) {
    result.error = "bad query name: " + name;
    close(fd);
    return result;
  }
  std::string query;
  query.reserve(12 + qname.size() + 4);
  auto append_u16 = [&query](uint16_t v) {
    query.push_back(static_cast<char>(v >> 8));
    query.push_back(static_cast<char>(v & 0xff));
  };
  append_u16(id);
  append_u16(0x0100);  // RD
  append_u16(1);       // QDCOUNT
  append_u16(0);
  append_u16(0);
  append_u16(0);
  query += qname;
  append_u16(qtype->code);
  append_u16(kClassIn);

  ssize_t sent;
  do {
    sent = send(fd, query.data(), query.size(), 0);
  } while (sent < 0 && errno == EINTR);
  if (sent < 0 || static_cast<size_t>(sent) != query.size()) {
    result.error = std::string(shown + ": send: ") +
                   (sent < 0 ? std::strerror(errno) : "short write");
    close(fd);
    return result;
  }

  uint8_t msg[65535];
  ssize_t got;
  do {
    got = recv(fd, msg, sizeof msg, 0);
  } while (got < 0 && errno == EINTR);
  close(fd);
  if (got < 0) {
    result.error = shown + ": " + std::strerror(errno);
    return result;
  }
  const size_t n = static_cast<size_t>(got);
  if (n < 12) {
    result.error = shown + ": short response (" + std::to_string(n) + " bytes)";
    return result;
  }
  if (get_u16(msg) != id) {
    result.error = shown + ": response id mismatch";
    return result;
  }
  const uint16_t flags = get_u16(msg + 2);
  if (flags & 0x0200) {
    result.error = shown + ": response truncated (TC bit set); retry over TCP";
    return result;
  }
  const char *rc = rcode_text(flags & 0x000f);
  result.rcode = rc ? rc : "RCODE" + std::to_string(flags & 0x000f);

  const uint16_t qdcount = get_u16(msg + 4);
  const uint16_t ancount = get_u16(msg + 6);
  size_t off = 12;
  for (uint16_t i = 0; i < qdcount; ++i) {
    std::string skipped;
    if (!read_name(msg, n, &off, &skipped) || off + 4 > n) {
      result.error = shown + ": malformed question section";
      result.answers.clear();
      return result;
    }
    off += 4;
  }
  for (uint16_t i = 0; i < ancount; ++i) {
    std::string aname;
    if (!read_name(msg, n, &off, &aname) || off + 10 > n) {
      result.error = shown + ": malformed answer section";
      result.answers.clear();
      return result;
    }
    const uint16_t atype = get_u16(msg + off);
    const uint16_t aclass = get_u16(msg + off + 2);
    const uint32_t attl = get_u32(msg + off + 4);
    const uint16_t rdlen = get_u16(msg + off + 8);
    off += 10;
    if (off + rdlen > n) {
      result.error = shown + ": malformed answer section";
      result.answers.clear();
      return result;
    }
    DnsAnswer answer;
    answer.name = aname;
    answer.type = aclass == kClassIn ? type_text(atype)
                                     : "CLASS" + std::to_string(aclass);
    answer.ttl = attl;
    answer.data = render_rdata(msg, n, off, rdlen, atype);
    result.answers.push_back(std::move(answer));
    off += rdlen;
  }
  return result;
}

} // namespace lmnet
