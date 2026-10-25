// lmnet: classic Linux network tools plus structured, scriptable
// introspection in one statically linked CLI.
#include "net.hpp"
#include "dslvm.hpp"
#include "schema_embedded.hpp"

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
      "       lmnet ifaddrs         # interfaces with addresses (ip addr-lite)\n"
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
