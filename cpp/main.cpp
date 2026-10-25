// lmnet: classic Linux network tools plus structured, scriptable
// introspection in one statically linked CLI.
#include "net.hpp"
#include "dns.hpp"
#include "sockets.hpp"
#include "dslvm.hpp"
#include "schema_embedded.hpp"

#include <cctype>
#include <cstdio>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

extern "C" int lmnet_ping_main(int argc, char **argv);
extern "C" int lmnet_tracepath_main(int argc, char **argv);

namespace {
using dslvm::Args;
using dslvm::Value;

struct Host {
  std::vector<std::unique_ptr<lmnet::Iface>> ifaces;
  std::vector<std::unique_ptr<std::vector<lmnet::Iface *>>> iface_lists;
  std::vector<std::unique_ptr<lmnet::Socket>> sockets;
  std::vector<std::unique_ptr<std::vector<lmnet::Socket *>>> socket_lists;
  std::vector<std::unique_ptr<lmnet::DnsResult>> dns_results;
  std::vector<std::unique_ptr<std::vector<lmnet::DnsAnswer *>>> dns_answer_lists;
  template <class T>
  Value hold(std::vector<std::unique_ptr<T>> &arena, const char *type, T value) {
    if (arena.size() >= 65536)
      throw dslvm::Error(std::string(type) + " object limit exceeded (65536)");
    arena.push_back(std::make_unique<T>(std::move(value)));
    return Value::object(type, arena.back().get());
  }
};

template <class T> T *self(void *p) { return static_cast<T *>(p); }

lmnet::Iface *iface_of(void *p, const char *who) {
  auto *i = self<lmnet::Iface>(p);
  if (!i) throw dslvm::Error(std::string(who) + ": stale Iface handle");
  return i;
}

lmnet::DnsResult *dns_result_of(void *p, const char *who) {
  auto *r = self<lmnet::DnsResult>(p);
  if (!r) throw dslvm::Error(std::string(who) + ": stale DnsResult handle");
  return r;
}

lmnet::DnsAnswer *dns_answer_of(void *p, const char *who) {
  auto *a = self<lmnet::DnsAnswer>(p);
  if (!a) throw dslvm::Error(std::string(who) + ": stale DnsAnswer handle");
  return a;
}

std::string json_escape(const std::string &s) {
  std::string out;
  for (unsigned char c : s) {
    switch (c) {
    case '"': out += "\\\""; break;
    case '\\': out += "\\\\"; break;
    case '\n': out += "\\n"; break;
    case '\r': out += "\\r"; break;
    case '\t': out += "\\t"; break;
    default:
      if (c < 0x20) {
        char buf[8];
        std::snprintf(buf, sizeof buf, "\\u%04x", c);
        out += buf;
      } else out += static_cast<char>(c);
    }
  }
  return out;
}
std::string json_string(const std::string &s) { return "\"" + json_escape(s) + "\""; }

std::string iface_json(const lmnet::Iface &i) {
  return std::string("{\"name\":") + json_string(i.name) +
         ",\"addr\":" + json_string(i.addr) +
         ",\"mtu\":" + std::to_string(i.mtu) +
         ",\"up\":" + (i.up ? "true" : "false") +
         ",\"loopback\":" + (i.loopback ? "true" : "false") + "}";
}

std::string socket_json(const lmnet::Socket &s) {
  return std::string("{\"proto\":") + json_string(s.proto) +
         ",\"local\":" + json_string(s.local) +
         ",\"remote\":" + json_string(s.remote) +
         ",\"state\":" + json_string(s.state) +
         ",\"pid\":" + std::to_string(s.pid) +
         ",\"process\":" + json_string(s.process) + "}";
}

std::string dns_answer_json(const lmnet::DnsAnswer &a) {
  return std::string("{\"name\":") + json_string(a.name) +
         ",\"type\":" + json_string(a.type) +
         ",\"ttl\":" + std::to_string(a.ttl) +
         ",\"data\":" + json_string(a.data) + "}";
}

// ---- DSL registry: the schema implementation ----
void register_host(dslvm::Registry &reg, Host &host) {
  reg.context("net", "Net");

  reg.function("println", {"string"}, "void", [](Args &args) {
    std::cout << args[0].s << "\n";
    return Value::none();
  });
  reg.method("Net", "dns_lookup", {"string"}, "StrList", [&reg](void *, Args &args) {
    std::string error;
    auto addrs = lmnet::dns_lookup(args[0].s, error);
    if (!error.empty())
      throw dslvm::Error("dns_lookup: " + error);
    return Value::object("StrList", reg.std_collections().make_str_list(std::move(addrs)));
  });

  reg.method("Net", "interfaces", {}, "IfaceList", [&host](void *, Args &) {
    std::string error;
    auto ifaces = lmnet::interfaces(error);
    if (!error.empty())
      throw dslvm::Error("interfaces: " + error);
    std::vector<lmnet::Iface *> ptrs;
    for (auto &iface : ifaces) {
      host.ifaces.push_back(std::make_unique<lmnet::Iface>(std::move(iface)));
      ptrs.push_back(host.ifaces.back().get());
    }
    return host.hold(host.iface_lists, "IfaceList", std::move(ptrs));
  });

  const auto iface_method = [&reg](const char *name, auto impl) {
    reg.method("Iface", name, {}, "string", [name, impl](void *s, Args &) {
      return Value::string(impl(iface_of(s, name)));
    });
  };
  iface_method("name", [](const lmnet::Iface *i) { return i->name; });
  iface_method("addr", [](const lmnet::Iface *i) { return i->addr; });
  reg.method("Iface", "mtu", {}, "int", [](void *s, Args &) {
    return Value::integer(iface_of(s, "mtu")->mtu);
  });
  reg.method("Iface", "up", {}, "bool", [](void *s, Args &) {
    return Value::boolean(iface_of(s, "up")->up);
  });
  reg.method("Iface", "loopback", {}, "bool", [](void *s, Args &) {
    return Value::boolean(iface_of(s, "loopback")->loopback);
  });

  reg.method("IfaceList", "len", {}, "int", [](void *s, Args &) {
    return Value::integer(static_cast<int64_t>(self<std::vector<lmnet::Iface *>>(s)->size()));
  });
  reg.method("IfaceList", "at", {"int"}, "Iface", [](void *s, Args &args) {
    const auto *v = self<std::vector<lmnet::Iface *>>(s);
    const int64_t i = args[0].i;
    if (i < 0 || static_cast<size_t>(i) >= v->size())
      throw dslvm::Error("IfaceList.at index out of range");
    return Value::object("Iface", v->at(static_cast<size_t>(i)));
  });

  reg.method("Net", "sockets", {"string", "bool"}, "SocketList", [&host](void *, Args &args) {
    std::string error;
    auto socks = lmnet::socket_table(args[0].s, args[1].b, error);
    if (!error.empty())
      throw dslvm::Error("sockets: " + error);
    std::vector<lmnet::Socket *> ptrs;
    for (auto &sock : socks) {
      host.sockets.push_back(std::make_unique<lmnet::Socket>(std::move(sock)));
      ptrs.push_back(host.sockets.back().get());
    }
    return host.hold(host.socket_lists, "SocketList", std::move(ptrs));
  });

  const auto socket_method = [&reg](const char *name, auto impl) {
    reg.method("Socket", name, {}, "string", [name, impl](void *s, Args &) {
      return Value::string(impl(self<lmnet::Socket>(s)));
    });
  };
  socket_method("proto", [](const lmnet::Socket *s) { return s->proto; });
  socket_method("local", [](const lmnet::Socket *s) { return s->local; });
  socket_method("remote", [](const lmnet::Socket *s) { return s->remote; });
  socket_method("state", [](const lmnet::Socket *s) { return s->state; });
  socket_method("process", [](const lmnet::Socket *s) { return s->process; });
  reg.method("Socket", "pid", {}, "int", [](void *s, Args &) {
    return Value::integer(self<lmnet::Socket>(s)->pid);
  });
  reg.method("SocketList", "len", {}, "int", [](void *s, Args &) {
    return Value::integer(static_cast<int64_t>(self<std::vector<lmnet::Socket *>>(s)->size()));
  });
  reg.method("SocketList", "at", {"int"}, "Socket", [](void *s, Args &args) {
    const auto *v = self<std::vector<lmnet::Socket *>>(s);
    const int64_t i = args[0].i;
    if (i < 0 || static_cast<size_t>(i) >= v->size())
      throw dslvm::Error("SocketList.at index out of range");
    return Value::object("Socket", v->at(static_cast<size_t>(i)));
  });

  reg.method("Net", "dns_query", {"string", "string", "string"}, "DnsResult",
             [&host](void *, Args &args) {
               if (!lmnet::dns_type_known(args[1].s))
                 throw dslvm::Error("dns_query: unsupported query type: " + args[1].s);
               auto result = lmnet::dns_query(args[0].s, args[1].s, args[2].s);
               // Network/parse failures come back in error() (dig semantics:
               // a failed query is data, like NXDOMAIN), never a crash.
               // Hold the result first: the answer list points into it.
               Value res = host.hold(host.dns_results, "DnsResult", std::move(result));
               auto *held = self<lmnet::DnsResult>(res.obj);
               std::vector<lmnet::DnsAnswer *> ptrs;
               ptrs.reserve(held->answers.size());
               for (auto &answer : held->answers)
                 ptrs.push_back(&answer);
               host.hold(host.dns_answer_lists, "DnsAnswerList", std::move(ptrs));
               return res;
             });

  reg.method("DnsResult", "rcode", {}, "string", [](void *s, Args &) {
    return Value::string(dns_result_of(s, "rcode")->rcode);
  });
  reg.method("DnsResult", "error", {}, "string", [](void *s, Args &) {
    return Value::string(dns_result_of(s, "error")->error);
  });
  reg.method("DnsResult", "answers", {}, "DnsAnswerList", [&host](void *s, Args &) {
    auto *result = dns_result_of(s, "answers");
    std::vector<lmnet::DnsAnswer *> ptrs;
    ptrs.reserve(result->answers.size());
    for (auto &answer : result->answers)
      ptrs.push_back(&answer);
    return host.hold(host.dns_answer_lists, "DnsAnswerList", std::move(ptrs));
  });

  const auto dns_method = [&reg](const char *name, auto impl) {
    reg.method("DnsAnswer", name, {}, "string", [name, impl](void *s, Args &) {
      return Value::string(impl(dns_answer_of(s, name)));
    });
  };
  dns_method("name", [](const lmnet::DnsAnswer *a) { return a->name; });
  dns_method("type", [](const lmnet::DnsAnswer *a) { return a->type; });
  dns_method("data", [](const lmnet::DnsAnswer *a) { return a->data; });
  reg.method("DnsAnswer", "ttl", {}, "int", [](void *s, Args &) {
    return Value::integer(dns_answer_of(s, "ttl")->ttl);
  });
  reg.method("DnsAnswerList", "len", {}, "int", [](void *s, Args &) {
    return Value::integer(
        static_cast<int64_t>(self<std::vector<lmnet::DnsAnswer *>>(s)->size()));
  });
  reg.method("DnsAnswerList", "at", {"int"}, "DnsAnswer", [](void *s, Args &args) {
    const auto *v = self<std::vector<lmnet::DnsAnswer *>>(s);
    const int64_t i = args[0].i;
    if (i < 0 || static_cast<size_t>(i) >= v->size())
      throw dslvm::Error("DnsAnswerList.at index out of range");
    return Value::object("DnsAnswer", v->at(static_cast<size_t>(i)));
  });
}

void print_schema_summary(const dslvm::Registry &reg) {
  for (const auto &line : reg.signatures()) std::cout << line << "\n";
}

// Run a vendored tool main with an argv of ["tool", args...]. The mains own
// their output and exit codes; they never return to the dispatch loop.
[[noreturn]] void run_tool(int (*tool_main)(int, char **), const char *tool,
                           int argc, char **argv) {
  std::vector<std::string> storage;
  std::vector<char *> av;
  av.push_back(const_cast<char *>(tool));
  for (int i = 0; i < argc; ++i)
    storage.emplace_back(argv[i]);
  for (auto &s : storage)
    av.push_back(const_cast<char *>(s.c_str()));
  av.push_back(nullptr);
  exit(tool_main(static_cast<int>(av.size()) - 1, av.data()));
}
} // namespace

int main(int argc, char **argv) {
  Host host;
  dslvm::Registry reg;
  register_host(reg, host);
  const std::string usage =
      "usage: lmnet --version | --dsl-schema [--json] | --dsl-signatures\n"
      "       lmnet ping HOST [iputils ping options]\n"
      "       lmnet tracepath HOST [iputils tracepath options]\n"
      "       lmnet dns HOST        # resolve addresses (nslookup-lite)\n"
      "       lmnet dig NAME [TYPE] [@server]  # DNS query (dig-lite)\n"
      "       lmnet ifaddrs         # interfaces with addresses (ip addr-lite)\n"
      "       lmnet sockets [tcp|udp|unix] [--listen]  # socket tables (netstat/lsof -i-lite)\n"
      "       lmnet --dsl FILE [FILE ...]\n";
  if (argc == 2 && std::string(argv[1]) == "--version") {
    std::cout << "lmnet " LMNET_VERSION "\n";
    return std::cout ? 0 : 4;
  }
  if (argc >= 2 && std::string(argv[1]) == "--dsl-schema") {
    if (argc == 2) {
      print_schema_summary(reg);
      return std::cout ? 0 : 4;
    }
    if (argc == 3 && std::string(argv[2]) == "--json") {
      std::cout.write(reinterpret_cast<const char *>(lmnet::embedded_schema),
                      static_cast<std::streamsize>(lmnet::embedded_schema_size));
      return std::cout ? 0 : 4;
    }
    std::cerr << usage;
    return 2;
  }
  if (argc == 2 && std::string(argv[1]) == "--dsl-signatures") {
    for (const auto &signature : reg.signatures()) std::cout << signature << "\n";
    return 0;
  }
  if (argc >= 3 && std::string(argv[1]) == "ping")
    run_tool(lmnet_ping_main, "ping", argc - 2, argv + 2);
  if (argc >= 3 && std::string(argv[1]) == "tracepath")
    run_tool(lmnet_tracepath_main, "tracepath", argc - 2, argv + 2);
  if (argc == 3 && std::string(argv[1]) == "dns") {
    std::string error;
    auto addrs = lmnet::dns_lookup(argv[2], error);
    if (!error.empty()) {
      std::cerr << "lmnet dns: " << argv[2] << ": " << error << "\n";
      return 1;
    }
    for (const auto &a : addrs) std::cout << a << "\n";
    return 0;
  }
  if (argc >= 3 && std::string(argv[1]) == "dig") {
    if (argc > 6) {
      std::cerr << usage;
      return 2;
    }
    const std::string name = argv[2];
    std::string type = "A";
    bool type_set = false;
    std::string server;
    for (int i = 3; i < argc; ++i) {
      std::string arg = argv[i];
      if (!arg.empty() && arg[0] == '@') {
        if (!server.empty()) {
          std::cerr << usage;
          return 2;
        }
        server = arg.substr(1);
        continue;
      }
      if (lmnet::dns_type_known(arg) && !type_set) {
        std::string up;
        for (char c : arg) up.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
        type = up;
        type_set = true;
        continue;
      }
      if (!server.empty()) {
        std::cerr << usage;
        return 2;
      }
      server = arg;
    }
    auto result = lmnet::dns_query(name, type, server);
    if (!result.error.empty()) {
      std::cerr << "lmnet dig: " << name << ": " << result.error << "\n";
      return 1;
    }
    std::cout << "{\"rcode\":" << json_string(result.rcode) << ",\"answers\":[";
    for (size_t i = 0; i < result.answers.size(); ++i) {
      if (i) std::cout << ",";
      std::cout << dns_answer_json(result.answers[i]);
    }
    std::cout << "]}\n";
    return std::cout ? 0 : 4;
  }
  if (argc == 2 && std::string(argv[1]) == "ifaddrs") {
    std::string error;
    auto ifaces = lmnet::interfaces(error);
    if (!error.empty()) {
      std::cerr << "lmnet ifaddrs: " << error << "\n";
      return 1;
    }
    std::cout << "[";
    for (size_t i = 0; i < ifaces.size(); ++i) {
      if (i) std::cout << ",";
      std::cout << iface_json(ifaces[i]);
    }
    std::cout << "]\n";
    return std::cout ? 0 : 4;
  }
  if (argc >= 2 && std::string(argv[1]) == "sockets") {
    std::string proto_filter;
    bool only_listen = false;
    for (int i = 2; i < argc; ++i) {
      const std::string arg = argv[i];
      if (arg == "--listen")
        only_listen = true;
      else if (arg == "tcp" || arg == "udp" || arg == "unix")
        proto_filter = arg;
      else {
        std::cerr << usage;
        return 2;
      }
    }
    std::string error;
    auto socks = lmnet::socket_table(proto_filter, only_listen, error);
    if (!error.empty()) {
      std::cerr << "lmnet sockets: " << error << "\n";
      return 1;
    }
    std::cout << "[";
    for (size_t i = 0; i < socks.size(); ++i) {
      if (i) std::cout << ",";
      std::cout << socket_json(socks[i]);
    }
    std::cout << "]\n";
    return std::cout ? 0 : 4;
  }
  if (argc >= 3 && std::string(argv[1]) == "--dsl") {
    for (int i = 2; i < argc; ++i) {
      if (std::string(argv[i]).empty() || std::string(argv[i]).rfind("--", 0) == 0) {
        std::cerr << usage;
        return 2;
      }
    }
    const std::string schema(reinterpret_cast<const char *>(lmnet::embedded_schema),
                             lmnet::embedded_schema_size);
    dslvm::Context context;
    context.set("net", &host);
    std::vector<dslvm::Program> programs;
    for (int i = 2; i < argc; ++i) {
      try {
        programs.push_back(dslvm::Program::load(dslvm::read_file(argv[i]), schema, reg));
      } catch (const dslvm::Error &error) {
        return dslvm::report_error("load", error);
      }
    }
    for (const auto &program : programs) {
      try {
        program.run(context, reg);
      } catch (const dslvm::Error &error) {
        return dslvm::report_error("run", error);
      }
      dslvm::report_ok();
    }
    return 0;
  }
  std::cerr << usage;
  return 2;
}
