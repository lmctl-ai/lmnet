#include "counters.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <set>
#include <sstream>
#include <utility>

namespace lmnet {
namespace {

bool is_number(const std::string &w) {
  if (w.empty()) return false;
  size_t i = (w[0] == '-') ? 1 : 0;
  if (i == w.size()) return false;
  for (; i < w.size(); ++i)
    if (!std::isdigit(static_cast<unsigned char>(w[i]))) return false;
  return true;
}

// /proc/net/snmp and /proc/net/netstat use the kernel's two-line-per-section
// format: a header line ("Ip: Forwarding DefaultTTL ...") immediately
// followed by a values line with the identical leading protocol prefix
// ("Ip: 2 64 ..."). Fields and values pair positionally; a header whose
// values line never comes (or comes malformed) is skipped.
void parse_snmp_style(const char *path, std::vector<Counter> &out,
                      std::set<std::string> &seen, int &sources) {
  std::ifstream in(path);
  if (!in) return; // source missing: degrade gracefully
  ++sources;
  std::string prefix;
  std::vector<std::string> fields;
  bool have_header = false;
  std::string line;
  while (std::getline(in, line)) {
    std::istringstream tok(line);
    std::string lead, word;
    if (!(tok >> lead) || lead.empty() || lead.back() != ':') {
      have_header = false; // malformed line breaks any pending pair
      continue;
    }
    lead.pop_back();
    std::vector<std::string> words;
    while (tok >> word) words.push_back(word);
    if (words.empty()) {
      have_header = false;
      continue;
    }
    if (!std::all_of(words.begin(), words.end(), is_number)) {
      // header line: the values line must follow with the same prefix
      prefix = lead;
      fields = std::move(words);
      have_header = true;
      continue;
    }
    if (!have_header || prefix != lead) {
      have_header = false;
      continue;
    }
    const size_t n = std::min(fields.size(), words.size());
    for (size_t i = 0; i < n; ++i) {
      const std::string key = prefix + "." + fields[i];
      if (!seen.insert(key).second) continue; // first occurrence wins
      Counter c;
      c.name = key;
      c.value = std::strtoll(words[i].c_str(), nullptr, 10);
      out.push_back(std::move(c));
    }
    have_header = false;
  }
}

// /proc/net/snmp6 is single-line-per-counter: "Ip6InReceives 12345". Names
// are already unique, so the key is the name as-is.
void parse_snmp6(const char *path, std::vector<Counter> &out,
                 std::set<std::string> &seen, int &sources) {
  std::ifstream in(path);
  if (!in) return; // source missing: degrade gracefully
  ++sources;
  std::string line;
  while (std::getline(in, line)) {
    std::istringstream tok(line);
    std::string name, value;
    if (!(tok >> name >> value) || !is_number(value)) continue;
    if (!seen.insert(name).second) continue; // first occurrence wins
    Counter c;
    c.name = name;
    c.value = std::strtoll(value.c_str(), nullptr, 10);
    out.push_back(std::move(c));
  }
}

} // namespace

std::vector<Counter> counters(std::string &error) {
  error.clear();
  std::vector<Counter> out;
  std::set<std::string> seen;
  int sources = 0;
  parse_snmp_style("/proc/net/snmp", out, seen, sources);
  parse_snmp_style("/proc/net/netstat", out, seen, sources);
  parse_snmp6("/proc/net/snmp6", out, seen, sources);
  if (sources == 0) {
    error = "no counter sources readable (/proc/net/snmp, /proc/net/netstat, "
            "/proc/net/snmp6)";
    return out;
  }
  std::sort(out.begin(), out.end(),
            [](const Counter &a, const Counter &b) { return a.name < b.name; });
  return out;
}

} // namespace lmnet
