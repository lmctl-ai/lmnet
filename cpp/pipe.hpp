#pragma once
// lmnet TCP stdio bridge (nc-lite): connect or listen, then relay bytes
// between stdin/stdout and one socket with a poll() loop. Also the blocking
// socket objects behind the DSL `net.tcp_connect`/`net.tcp_listen` surface.
// Pure C++; POSIX sockets only (raw byte I/O, no text processing), so IPv6
// rides the same code path.

#include <cstdint>
#include <string>

namespace lmnet {

// Blocking TCP connection for scripts: send/recv bytes, close idempotently.
// recv() blocks until data arrives or the peer closes ("" marks EOF) and is
// implemented with poll(), never a spin.
class TcpConn {
public:
  TcpConn() = default;
  explicit TcpConn(int fd) : fd_(fd) {}
  TcpConn(TcpConn &&other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
  TcpConn &operator=(TcpConn &&other) noexcept;
  TcpConn(const TcpConn &) = delete;
  TcpConn &operator=(const TcpConn &) = delete;
  ~TcpConn() { reset(); }

  int fd() const { return fd_; }
  bool ok() const { return fd_ >= 0; }

  // send() throws dslvm::Error via `fail` on a closed socket or write error;
  // the whole string is delivered before it returns.
  void send(const std::string &data, void (*fail)(const std::string &));
  // recv() returns up to n bytes; "" means EOF or an orderly peer close.
  std::string recv(int64_t n, void (*fail)(const std::string &));
  // Idempotent: further send/recv throw "TcpConn: closed".
  void close() { reset(); }

private:
  void reset();
  int fd_ = -1;
};

// Blocking acceptor for scripts: bind 0.0.0.0:port, listen, accept one
// connection at a time.
class TcpListener {
public:
  TcpListener() = default;
  explicit TcpListener(int fd) : fd_(fd) {}
  TcpListener(TcpListener &&other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
  TcpListener &operator=(TcpListener &&other) noexcept;
  TcpListener(const TcpListener &) = delete;
  TcpListener &operator=(const TcpListener &) = delete;
  ~TcpListener() { reset(); }

  int fd() const { return fd_; }
  bool ok() const { return fd_ >= 0; }
  void close() { reset(); }

private:
  friend TcpListener tcp_listen(int port, std::string &error);
  friend bool tcp_accept(TcpListener &listener, TcpConn &conn, std::string &error);
  void reset();
  int fd_ = -1;
};

// Resolve `host` and open one blocking, connected socket; -1 with `error`
// set on resolution failure or when no address accepts the connection.
int tcp_connect_fd(const std::string &host, int port, std::string &error);

// Bind 0.0.0.0:port (SO_REUSEADDR) and listen; -1 with `error` set on
// failure. The returned listener owns the socket.
TcpListener tcp_listen(int port, std::string &error);

// Block until a client connects; false with `error` set on failure.
bool tcp_accept(TcpListener &listener, TcpConn &conn, std::string &error);

// `lmnet pipe HOST PORT`: connect, then relay stdin<->socket->stdout until
// both directions finish. Returns a process exit code: 0 when the relay ends
// cleanly, 1 with `error` set on resolution/connect failure.
int pipe_connect(const std::string &host, int port, std::string &error);

// `lmnet pipe --listen PORT [--forever]`: bind/listen, accept one
// connection, relay it, exit — with `forever` loop back to accept the next
// connection. Returns a process exit code: 0 on clean shutdown, 1 with
// `error` set on bind/accept failure.
int pipe_listen(int port, bool forever, std::string &error);

} // namespace lmnet
