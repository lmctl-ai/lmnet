# Examples

Runnable lmscript programs, one per scenario. Each compiles to bytecode and
runs against the `lmnet` host:

```sh
lmscript examples/dns-lookup.lms build/dns-lookup.dslb
lmnet --dsl build/dns-lookup.dslb
```

The `install="github:lmctl-ai/lmnet@latest"` line in each script pins the
host CLI the same way lmscript resolves any other tool.

- `dns-lookup.lms` — resolve `localhost` and print every address
- `counters.lms` — dump the kernel's protocol counters (netstat -s/nstat
  coverage; the count varies by kernel, so only the framing lines are pinned)
- `interfaces.lms` — enumerate interfaces, addresses, MTUs and flags
- `link.lms` — dump every link device with RX/TX counters (unlike
  `interfaces`, this covers link devices with no addresses too)
- `neigh.lms` — dump the ARP/NDP neighbor table (prints an empty table
  cleanly on a fresh machine)
- `sockets-summary.lms` — print the `ss -s`-lite socket aggregate (per-family
  counts and TCP state histogram; counts vary by host, so only the framing
  lines are pinned)
- `rule.lms` — dump the policy routing rules (ip rule-lite; the pref-0
  local rule always exists, so its line is pinned)
- `scan.lms` — TCP-connect scan of one loopback port via `net.scan` /
  `net.check` (works offline; the verdict depends on the machine, so only
  the framing lines are pinned)
- `trace.lms` — traceroute 127.0.0.1 and print the hop list (degrades to an
  error message without raw-socket permission)

`./test.sh` compiles and runs every example as part of the check suite.
