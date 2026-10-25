# lmnet

Classic Linux network tools plus structured, scriptable introspection in one
statically-linked, dependency-free executable. Not a network monitor daemon —
a debug and research CLI you can also drive from
[lmscript](https://github.com/lmctl-ai).

The long-term goal is to combine the common Linux network toolbox (`ping`,
`ip`, `netstat`, `lsof`, `traceroute`, `mtr`, `tracepath`, `dig`,
`nslookup`, `iftop`, `iperf3`) behind one CLI and one scripting surface.
Today lmnet ships the first slices: the iputils `ping` and `tracepath`
engines, the real iperf3 engine, plus `dns` (nslookup-lite), `dig`
(dig-lite: real DNS messages over
UDP), `ifaddrs` (`ip addr`-lite) built on libc, `route` (`ip route`-lite
over rtnetlink), `neigh` (`ip neigh`-lite over rtnetlink), `link`
(`ip -s link`-lite over rtnetlink), and `trace` (traceroute-lite: UDP probes, ICMP answers,
structured hop list). Packet capture stays
with the sibling project lmshark (Wireshark/tcpdump territory); URL fetching
will be lmcurl.

## Build

```sh
scripts/sync-iputils.sh   # download the pinned iputils source (third_party/, git-ignored)
scripts/sync-iperf3.sh   # download the pinned iperf3 source (third_party/, git-ignored)
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Produces `build/lmnet`: one statically linked executable (`ldd` reports
"not a dynamic executable" on Linux; only libc at runtime).

## CLI

```
lmnet --version
lmnet --dsl-schema [--json]
lmnet --dsl-signatures
lmnet ping HOST [iputils ping options]        # the real iputils ping engine
lmnet tracepath HOST [iputils tracepath options]
lmnet iperf3 [iperf3 options]                   # the real iperf3 engine (client/server)
lmnet dns HOST                                # resolve addresses (nslookup-lite)
lmnet dig NAME [TYPE] [@server]               # DNS query as JSON (dig-lite)
lmnet ifaddrs                                 # interfaces + addresses as JSON (ip addr-lite)
lmnet route                                   # routing tables as JSON (ip route-lite)
lmnet neigh                                   # neighbor table as JSON (ip neigh-lite)
lmnet link                                    # link devices + RX/TX counters as JSON (ip -s link-lite)
lmnet sockets [tcp|udp|unix] [--listen]       # socket tables as JSON (netstat/lsof -i-lite)
lmnet trace HOST [maxttl]                     # UDP-probe traceroute as JSON (traceroute-lite)
lmnet --dsl FILE [FILE ...]
```

`ping` and `tracepath` are the upstream iputils binaries-in-a-binary: same
flags, same output, same behavior (including the usual raw-socket permission
requirements). `iperf3` is the upstream iperf 3.22 engine likewise embedded
— client and server, same flags and output (built without OpenSSL auth and
without SCTP, matching iperf's own defaults). `dns`, `ifaddrs`, `route`, `neigh`, and `link` are structured and print one JSON
array; `dig` sends a real RFC 1035 query (UDP, 3 s timeout, connected socket
so a dead resolver fails fast) and prints one JSON object
`{"rcode": ..., "answers": [{name, type, ttl, data}]}` — try
`lmnet dig example.com A @1.1.1.1`. `route` dumps every kernel routing table
over rtnetlink (IPv4 + IPv6, `ip route show table all`-style) as
`[{dest, via, dev, proto, scope, metric, table, prefsrc}]`. `neigh` dumps the
ARP/NDP neighbor table over rtnetlink (`ip neigh`/`arp`-lite) as
`[{ip, dev, state, mac, family, router, proxy}]`, where `state` is the
lowercased kernel NUD state, `mac` is "" when the kernel has no link-layer
address, and `router`/`proxy` mirror the NTF flags. `link` dumps every link
device over rtnetlink (`ip -s link`-lite) as `[{name, index, mtu, up,
loopback, mac, txqlen, rx_bytes, rx_packets, rx_errors, rx_dropped,
tx_bytes, tx_packets, tx_errors, tx_dropped}]` — unlike `ifaddrs` (which
lists interfaces that carry addresses), `link` covers every link device,
including ones with no addresses at all, and adds the kernel's 64-bit
RX/TX counters from `rtnl_link_stats64` (`mac` is "" when the device has
no link-layer address; counters are 0 when the kernel omits `IFLA_STATS64`).
`trace` is a
structured traceroute-lite: one UDP probe per TTL to a high unprivileged port
(33434+ttl), ICMP answers on a raw socket, printed as
`{"dest_ip": ..., "hops": [{ttl, from, rtt_ms, reached}]}` — a silent hop is
`{"from": "", "rtt_ms": -1}` and `reached` marks the destination answering
port-unreachable. IPv4-only in this slice (IPv6-only names fail cleanly), and
reading ICMP needs root or CAP_NET_RAW. Unlike the vendored `tracepath`,
`trace` is structured data: every hop is a DSL object via `net.trace`.

## Scripting

```lmscript
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
let addrs = net.dns_lookup("example.com");
println(str(addrs.len()) + " addresses");
let ifs = net.interfaces();
for (i in range(0, ifs.len())) {
  println(ifs.at(i).name() + " " + ifs.at(i).addr());
}
end _dsl_
savedsl(p, "build/show.dslb");
```

The lmcode std catalog is available in every script (`str_*`, `math_*`,
`file_*`, `str_list`/`str_map`, ...) without declaring it in the host schema.
See `examples/` for runnable scripts.

## Platform support

Linux only, x86_64 and arm64. The vendored upstream tools (iputils, and
iproute2/net-tools later) are Linux-specific; there is no native macOS or
Windows port upstream to wrap.

## Repository layout

- `cpp/` — the CLI host: DSL VM integration, `dns`/`ifaddrs` introspection
- `schema/lmnet.host.json` — the host DSL fragment (merged with the lmcode
  std catalog into the embedded schema at configure time)
- `examples/` — lmscript examples
- `scripts/` — vendoring (iputils/iperf3 sources, lmcode-cpp SDK) and compiler selection
- `third_party/` — downloaded upstream sources (git-ignored, pinned by `iputils.lock` / `iperf3.lock`)

## Roadmap

- `ip` — `route` delivered over rtnetlink as `lmnet route` / `net.routes`,
  `neigh` as `lmnet neigh` / `net.neighbors`, and `link` as `lmnet link` /
  `net.links` (`addr` already covered by `ifaddrs`); iproute2 sources remain
- `traceroute`/`mtr` — traceroute-lite delivered over UDP/ICMP as
  `lmnet trace` / `net.trace` (IPv4, one probe per TTL); mtr-style repeated
  probes remain
- `netstat`/`lsof` (socket tables from /proc) — delivered as `lmnet
  sockets` / `net.sockets` (tcp/udp/unix tables, LISTEN view, process
  attribution via /proc/<pid>/fd)
- `dig`/`nslookup` (full DNS messages, not just addresses) — delivered as
  dig-lite: `lmnet dig` + `net.dns_query` (nslookup-style name resolution
  remains the `dns` subcommand/`net.dns_lookup`)
- `iperf3` throughput engine delivered as the `lmnet iperf3` subcommand (real
  iperf 3.22 client/server); throughput runs as DSL objects remain

## License and company

lmnet-authored code is MIT licensed (see `LICENSE`). It builds against
iputils, whose per-tool licenses are listed in `THIRD_PARTY_NOTICES.md`
(ping BSD-3-Clause, tracepath GPL-2.0-or-later), and iperf3 (BSD-3-Clause);
the compiled executable is
a combined work whose distribution is governed by those upstream licenses.
Made by **Lattice Systems LLC**.

Compiler minimum: lmscript 0.2.420. The embedded schema contains only host declarations; string, math, collection and file std functions are implicit.
