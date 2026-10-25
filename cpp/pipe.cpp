#include "pipe.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstring>

namespace lmnet {
namespace {

constexpr size_t kBufSize = 65536;

void set_nonblocking(int fd) {
  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Relay between {stdin, socket} until both directions reach EOF. The socket
// is set non-blocking; stdin/stdout are already non-blocking. On stdin EOF
// the socket gets shutdown(SHUT_WR) so the peer sees EOF; once the socket
// hits EOF nothing more can be sent, so the remaining direction drains and
// the relay ends. The caller ignores SIGPIPE (a reset mid-write must not
// kill the process). Returns false with `error` set on an I/O failure.
bool relay(int sock, std::string &error) {
  char buf[kBufSize];
  pollfd fds[2] = {{STDIN_FILENO, POLLIN, 0}, {sock, POLLIN, 0}};
  bool stdin_open = true;   // still reading from stdin
  bool sock_wr = true;      // socket accepts writes (shutdown(SHUT_WR) not sent)
  bool sock_open = true;    // socket has not hit EOF yet

  while (stdin_open || sock_wr || sock_open) {
    int rc;
    do {
      rc = poll(fds, 2, -1);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
      error = std::strerror(errno);
      return false;
    }
    if (fds[0].revents) {
      // stdin: EOF -> tell the peer; data -> buffer it into the socket.
      if (fds[0].revents & POLLIN) {
        const ssize_t n = read(STDIN_FILENO, buf, sizeof buf);
        if (n > 0) {
          size_t off = 0;
          while (off < static_cast<size_t>(n)) {
            const ssize_t w = write(sock, buf + off, static_cast<size_t>(n) - off);
            if (w > 0) {
              off += static_cast<size_t>(w);
            } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
              pollfd wr{sock, POLLOUT, 0};
              do {
                rc = poll(&wr, 1, -1);
              } while (rc < 0 && errno == EINTR);
              if (rc <= 0 || (wr.revents & (POLLERR | POLLHUP | POLLNVAL))) {
                error = "socket closed while writing";
                return false;
              }
            } else if (w < 0 && errno == EINTR) {
              continue;
            } else {
              error = std::strerror(errno);
              return false;
            }
          }
        } else if (n == 0) {
          stdin_open = false;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
          error = std::strerror(errno);
          return false;
        }
      } else if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
        stdin_open = false;
      }
      if (!stdin_open && sock_wr) {
        sock_wr = false;
        if (shutdown(sock, SHUT_WR) != 0 && errno != ENOTCONN) {
          error = std::strerror(errno);
          return false;
        }
      }
    }
    if (fds[1].revents) {
      // socket: data -> stdout; EOF -> nothing more can be sent.
      if (fds[1].revents & (POLLIN | POLLERR | POLLHUP)) {
        const ssize_t n = read(sock, buf, sizeof buf);
        if (n > 0) {
          size_t off = 0;
          while (off < static_cast<size_t>(n)) {
            const ssize_t w = write(STDOUT_FILENO, buf + off, static_cast<size_t>(n) - off);
            if (w > 0) {
              off += static_cast<size_t>(w);
            } else if (w < 0 && errno == EINTR) {
              continue;
            } else {
              error = w < 0 ? std::strerror(errno) : "stdout closed";
              return false;
            }
          }
        } else if (n == 0) {
          sock_open = false;
        } else if (errno != EINTR) {
          error = std::strerror(errno);
          return false;
        }
      }
      if (fds[1].revents & POLLNVAL) {
        error = "socket closed unexpectedly";
        return false;
      }
      // Socket EOF: the peer is gone and nothing more can be sent, so the
      // relay is over (any stdin still open cannot deliver anywhere).
      if (!sock_open) break;
    }
  }
  return true;
}

} // namespace

TcpConn &TcpConn::operator=(TcpConn &&other) noexcept {
  reset();
  fd_ = other.fd_;
  other.fd_ = -1;
  return *this;
}

void TcpConn::reset() {
  if (fd_ >= 0) ::close(fd_);
  fd_ = -1;
}

void TcpConn::send(const std::string &data, void (*fail)(const std::string &)) {
  if (fd_ < 0) fail("TcpConn: closed");
  size_t off = 0;
  while (off < data.size()) {
    const ssize_t n = write(fd_, data.data() + off, data.size() - off);
    if (n > 0) {
      off += static_cast<size_t>(n);
    } else if (n < 0 && errno == EINTR) {
      continue;
    } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      pollfd pfd{fd_, POLLOUT, 0};
      int rc;
      do {
        rc = poll(&pfd, 1, -1);
      } while (rc < 0 && errno == EINTR);
      if (rc <= 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
        fail(std::string("TcpConn.send: ") + std::strerror(ECONNRESET));
    } else {
      fail(std::string("TcpConn.send: ") + std::strerror(errno));
    }
  }
}

std::string TcpConn::recv(int64_t n, void (*fail)(const std::string &)) {
  if (fd_ < 0) fail("TcpConn: closed");
  if (n <= 0) return "";
  std::string out;
  char buf[kBufSize];
  const size_t want =
      static_cast<size_t>(n) < sizeof buf ? static_cast<size_t>(n) : sizeof buf;
  // One read per call: blocks (via poll, so the VM never spins) until data
  // arrives, then returns up to n bytes; "" means EOF.
  for (;;) {
    const ssize_t r = read(fd_, buf, want);
    if (r > 0) {
      out.assign(buf, static_cast<size_t>(r));
      break;
    }
    if (r == 0) break;  // EOF
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      pollfd pfd{fd_, POLLIN, 0};
      int rc;
      do {
        rc = poll(&pfd, 1, -1);
      } while (rc < 0 && errno == EINTR);
      if (rc <= 0 || (pfd.revents & POLLNVAL))
        fail(std::string("TcpConn.recv: ") + std::strerror(errno));
      continue;  // readable (or EOF/HUP): loop around to read
    }
    fail(std::string("TcpConn.recv: ") + std::strerror(errno));
  }
  return out;
}

TcpListener &TcpListener::operator=(TcpListener &&other) noexcept {
  reset();
  fd_ = other.fd_;
  other.fd_ = -1;
  return *this;
}

void TcpListener::reset() {
  if (fd_ >= 0) ::close(fd_);
  fd_ = -1;
}

int tcp_connect_fd(const std::string &host, int port, std::string &error) {
  error.clear();
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo *res = nullptr;
  const int gai = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res);
  if (gai != 0) {
    error = gai_strerror(gai);
    return -1;
  }
  int fd = -1;
  int last_errno = 0;
  for (addrinfo *ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, SOCK_STREAM | SOCK_CLOEXEC, ai->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
    last_errno = errno;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) {
    error = last_errno ? std::strerror(last_errno) : "no usable address";
    return -1;
  }
  return fd;
}

TcpListener tcp_listen(int port, std::string &error) {
  error.clear();
  const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    error = std::strerror(errno);
    return TcpListener();
  }
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(static_cast<uint16_t>(port));
  if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof addr) != 0 ||
      listen(fd, 16) != 0) {
    error = std::strerror(errno);
    close(fd);
    return TcpListener();
  }
  return TcpListener(fd);
}

bool tcp_accept(TcpListener &listener, TcpConn &conn, std::string &error) {
  error.clear();
  const int lfd = listener.fd_;
  if (lfd < 0) {
    error = "listener closed";
    return false;
  }
  for (;;) {
    const int cfd = accept4(lfd, nullptr, nullptr, SOCK_CLOEXEC);
    if (cfd >= 0) {
      conn = TcpConn(cfd);
      return true;
    }
    if (errno == EINTR) continue;
    error = std::strerror(errno);
    return false;
  }
}

int pipe_connect(const std::string &host, int port, std::string &error) {
  error.clear();
  const int fd = tcp_connect_fd(host, port, error);
  if (fd < 0) return 1;
  std::signal(SIGPIPE, SIG_IGN);
  set_nonblocking(fd);
  const bool ok = relay(fd, error);
  const bool clean = ok && error.empty();
  if (!clean && error.empty()) error = "connection closed unexpectedly";
  close(fd);
  return clean ? 0 : 1;
}

int pipe_listen(int port, bool forever, std::string &error) {
  error.clear();
  TcpListener listener = tcp_listen(port, error);
  if (!listener.ok()) return 1;
  std::signal(SIGPIPE, SIG_IGN);
  do {
    TcpConn conn;
    if (!tcp_accept(listener, conn, error)) return 1;
    set_nonblocking(conn.fd());
    const bool ok = relay(conn.fd(), error);
    const bool clean = ok && error.empty();
    conn.close();
    if (!clean) {
      if (error.empty()) error = "connection closed unexpectedly";
      return 1;
    }
  } while (forever);
  return 0;
}

} // namespace lmnet
