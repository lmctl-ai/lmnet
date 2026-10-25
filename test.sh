#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
BUILD_DIR="${BUILD_DIR:-build}"
HOST="$BUILD_DIR/lmnet"
stat_size(){ stat -c %s "$1" 2>/dev/null || stat -f%z "$1"; }
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lmnet-test-XXXXXX")"
pass=0
FAKE_DNS_PID=""
ok(){ pass=$((pass+1)); echo "ok $pass - $1"; }
fail(){ echo "FAIL: $*" >&2; exit 1; }
cleanup(){ [ -z "$FAKE_DNS_PID" ] || kill "$FAKE_DNS_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

LMSCRIPT="$(scripts/select-compiler.sh)"
COMPILER_SOURCE="$LMSCRIPT"
scripts/sync-sdk.sh --verify >/dev/null || fail "SDK header pin mismatch"
ok "SDK headers match sdk.lock"
scripts/sync-iputils.sh --verify >/dev/null || fail "iputils pin mismatch"
ok "third_party/iputils matches iputils.lock"
scripts/sync-iperf3.sh --verify >/dev/null || fail "iperf3 pin mismatch"
ok "third_party/iperf3 matches iperf3.lock"

cmake -S . -B "$BUILD_DIR" -G Ninja -DCMAKE_BUILD_TYPE=Release >"$WORK/cmake.log" 2>&1 ||
  { tail -30 "$WORK/cmake.log" >&2; fail "cmake configure ($BUILD_DIR)"; }
cmake --build "$BUILD_DIR" -j2 >"$WORK/build.log" 2>&1 ||
  { tail -30 "$WORK/build.log" >&2; fail "cmake build ($BUILD_DIR)"; }
ok "host build ($BUILD_DIR)"
# install= prefers a matching host executable on PATH; put this test build first.
LOCAL_HOST_DIR="$(cd "$BUILD_DIR" && pwd)"
PATH="$LOCAL_HOST_DIR:$PATH"
export PATH

want_version="lmnet $(sed -n 's/^project(lmnet VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)"
[ "$("$HOST" --version)" = "$want_version" ] || fail "--version prints $want_version"
set +e; "$HOST" --version extra >/dev/null 2>&1; code=$?; set -e
[ "$code" = 2 ] || fail "--version with an extra argument exits 2 (got $code)"
ok "--version prints exactly '$want_version'"

"$HOST" --dsl-schema --json >"$WORK/embedded-schema.json" || fail "embedded schema print"
python3 - "$WORK/embedded-schema.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))  # strict: must be valid JSON
assert d.get('name')=='lmnet', d.get('name')
for t in ('Net','Iface','IfaceList','Route','RouteList'):
    assert t in d.get('types',{}), t
assert 'StrList' not in d['types'], 'standard types must stay implicit'
print('embedded schema: host-only Net/Iface/IfaceList and route types')
PY
cmp schema/lmnet.dsl.json "$WORK/embedded-schema.json" || fail "embedded schema differs from host-only schema bytes"
ok "--dsl-schema --json prints byte-identical host-only schema bytes"
"$HOST" --dsl-schema >"$WORK/schema-summary.txt" || fail "schema summary print"
python3 - "$WORK/schema-summary.txt" <<'PY'
import subprocess,sys
summary=open(sys.argv[1]).read()
sigs=subprocess.run(['build/lmnet','--dsl-signatures'],capture_output=True,text=True).stdout.splitlines()
missing=[]
for line in sigs:
    needle=line.split(' ',1)[1] if ' ' in line else line
    if needle not in summary: missing.append(needle)
assert not missing, missing
print('all', len(sigs), 'registry members listed in --dsl-schema summary')
PY
ok "--dsl-schema summary lists every registry member"
diff -u <("$LMSCRIPT" --dsl-signatures schema/lmnet.dsl.json) <("$HOST" --dsl-signatures) || fail "host/compiler signatures differ"
ok "typed registry signatures match compiler schema signatures"

# --- dns subcommand ---
out="$("$HOST" dns localhost)"
echo "$out" | grep -qx '127\.0\.0\.1' || echo "$out" | grep -q ':' || fail "dns localhost: $out"
[ -n "$out" ] || fail "dns localhost printed nothing"
ok "dns localhost resolves (offline via hosts/database)"

set +e; "$HOST" dns localhost.invalid-lmnet-test. >/dev/null 2>"$WORK/dns.err"; code=$?; set -e
[ "$code" = 1 ] || fail "unresolvable host exits 1 (got $code)"
grep -qi 'localhost.invalid-lmnet-test' "$WORK/dns.err" || fail "dns error names the host: $(cat "$WORK/dns.err")"
ok "dns failure exits 1 naming the host"

# --- dig subcommand (fake DNS server, offline) ---
# Tiny canned-response server: parses nothing, echoes the query id into a
# fixed response. example.com A -> NOERROR with one A answer; a query whose
# name contains "nxdom" -> NXDOMAIN with no answers.
cat > "$WORK/fakedns.py" <<'PY'
import socket, struct, sys
port = int(sys.argv[1]) if len(sys.argv) > 1 else 15353
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
qname = b"\x07example\x03com\x00"
question = qname + struct.pack(">HH", 1, 1)
def canned(rcode, answer):
    hdr = struct.pack(">HHHHHH", 0, 0x8180 | rcode, 1, 1 if answer else 0, 0, 0)
    if not answer:
        return hdr + question
    return (hdr + question + b"\xc0\x0c" +
            struct.pack(">HHIH", 1, 1, 300, 4) + bytes([93, 184, 216, 34]))
while True:
    datagram, peer = s.recvfrom(512)
    reply = canned(3, False) if b"nxdom" in datagram else canned(0, True)
    s.sendto(datagram[:2] + reply[2:], peer)  # echo the query's id
PY
python3 "$WORK/fakedns.py" 15353 &
FAKE_DNS_PID=$!
dig_out=""
for _ in $(seq 1 25); do
  if dig_out="$("$HOST" dig example.com A @127.0.0.1:15353 2>/dev/null)"; then break; fi
  sleep 0.2
done
[ -n "$dig_out" ] || fail "dig against fake server produced no output (server never came up?)"
DIG_OUT="$dig_out" python3 - <<'PY'
import json, os
r = json.loads(os.environ["DIG_OUT"])
assert r["rcode"] == "NOERROR", r
a = r["answers"]
assert len(a) == 1 and a[0]["name"] == "example.com.", r
assert a[0]["type"] == "A" and a[0]["ttl"] == 300, r
assert a[0]["data"] == "93.184.216.34", r
print("dig:", r["rcode"], a[0]["data"])
PY
ok "dig: JSON rcode NOERROR with canned A answer 93.184.216.34"

cat > "$WORK/dig.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
let r = net.dns_query("example.com", "A", "127.0.0.1:15353");
println("rcode: " + r.rcode());
let answers = r.answers();
if (answers.len() > 0) {
  println("data: " + answers.at(0).data());
  println("ttl: " + str(answers.at(0).ttl()));
}
end _dsl_
savedsl(p, "$WORK/dig.dslb");
EOF
"$LMSCRIPT" "$WORK/dig.lms" "$WORK/dig.dslb" >/dev/null || fail "dig bytecode compile"
out="$("$HOST" --dsl "$WORK/dig.dslb")"
grep -q '^rcode: NOERROR$' <<<"$out" || fail "dig bytecode rcode: $out"
grep -q '^data: 93\.184\.216\.34$' <<<"$out" || fail "dig bytecode data: $out"
grep -q '^ttl: 300$' <<<"$out" || fail "dig bytecode ttl: $out"
ok "bytecode: net.dns_query through the DSL"

set +e; out="$("$HOST" dig example.com A @127.0.0.1:9 2>&1)"; code=$?; set -e
[ "$code" = 1 ] || fail "dig to discard port exits 1 (got $code): $out"
grep -qi '127\.0\.0\.1\|unreachable\|refused\|timeout' <<<"$out" || \
  fail "dig error names the server/failure: $out"
ok "dig to a dead server exits 1 naming the failure"

nx_out="$("$HOST" dig nxdom.example.com A @127.0.0.1:15353)"
NX_OUT="$nx_out" python3 - <<'PY'
import json, os
r = json.loads(os.environ["NX_OUT"])
assert r["rcode"] == "NXDOMAIN" and r["answers"] == [], r
print("dig nxdom:", r["rcode"])
PY
ok "dig NXDOMAIN rcode surfaces in JSON"

cat > "$WORK/dnsoob.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
net.dns_query("example.com", "A", "127.0.0.1:15353").answers().at(5);
end _dsl_
savedsl(p, "$WORK/dnsoob.dslb");
EOF
"$LMSCRIPT" "$WORK/dnsoob.lms" "$WORK/dnsoob.dslb" >/dev/null || fail "compile"
set +e; out="$("$HOST" --dsl "$WORK/dnsoob.dslb" 2>&1)"; code=$?; set -e
[ "$code" = 3 ] && [[ "$out" == *'out of range'* ]] || fail "DnsAnswerList.at bounds (exit $code): $out"
ok "DnsAnswerList.at out of range refused (exit 3)"

set +e; "$HOST" dig example.com A @127.0.0.1:15353 extra extra2 >/dev/null 2>&1; code=$?; set -e
[ "$code" = 2 ] || fail "dig with too many args exits 2 (got $code)"
ok "dig argument overflow refused (exit 2)"

# --- ifaddrs subcommand ---
out="$("$HOST" ifaddrs)"
echo "$out" | python3 -c "
import json,sys
ifs=json.load(sys.stdin)
assert any(i['name']=='lo' and i['loopback'] and i['up'] for i in ifs), ifs
assert all(isinstance(i.get('mtu'),int) for i in ifs), ifs
print('ifaddrs:', len(ifs), 'interfaces, lo up+loopback')
"
ok "ifaddrs: JSON with lo up/loopback and MTUs"

# --- vendored tools (need ICMP/raw sockets; skip gracefully without) ---
if [ "$(id -u)" = 0 ] || [ -r /proc/sys/net/ipv4/ping_group_range ]; then
  if out="$("$HOST" ping 127.0.0.1 -c 1 -W 2 2>&1)" && echo "$out" | grep -q '1 received\|1 packets received'; then
    ok "ping 127.0.0.1 -c1 (iputils engine)"
  elif echo "$out" | grep -qi 'operation not permitted\|permission denied'; then
    echo "ok $((++pass)) - ping skipped: no ICMP permission in this environment"
  else
    fail "ping 127.0.0.1 failed: $out"
  fi
else
  echo "ok $((++pass)) - ping skipped: non-root without ping_group_range"
fi
"$HOST" tracepath -h >"$WORK/tp.txt" 2>&1 || true
grep -qi 'usage\|tracepath' "$WORK/tp.txt" || fail "tracepath -h shows usage: $(head -2 "$WORK/tp.txt")"
ok "tracepath engine runs (usage output)"

# --- iperf3 subcommand (real engine; loopback throughput needs no privileges) ---
set +e; out="$("$HOST" iperf3 --version 2>&1)"; code=$?; set -e
[ "$code" = 0 ] || fail "iperf3 --version exits 0 (got $code): $out"
grep -q 'iperf 3' <<<"$out" || fail "iperf3 --version prints the engine version: $out"
ok "iperf3 --version (engine $("$HOST" iperf3 --version 2>/dev/null | head -1))"

set +e; "$HOST" iperf3 --bogus >"$WORK/iperf3-bogus.out" 2>&1; code=$?; set -e
[ "$code" != 0 ] || fail "iperf3 --bogus exits nonzero"
ok "iperf3 unknown option refused (exit $code)"

# Real localhost run: one-shot server on 127.0.0.1, 1-second client. On
# Linux loopback this needs no caps; only a genuine failure (bind/loopback
# broken) after a retry is an error, not an environment skip.
IPERF3_SRV_PID=""
iperf3_server_cleanup(){ [ -z "$IPERF3_SRV_PID" ] || kill "$IPERF3_SRV_PID" 2>/dev/null || true; IPERF3_SRV_PID=""; }
out=""
for attempt in 1 2; do
  iperf3_server_cleanup
  "$HOST" iperf3 -s -1 -B 127.0.0.1 >"$WORK/iperf3-server.log" 2>&1 &
  IPERF3_SRV_PID=$!
  sleep 0.5
  set +e
  out="$("$HOST" iperf3 -c 127.0.0.1 -t 1 -i 0 2>&1)"
  code=$?
  set -e
  if [ "$code" = 0 ] && grep -q 'bits/sec' <<<"$out"; then
    break
  fi
  [ "$attempt" = 2 ] && fail "iperf3 localhost run failed (exit $code): $out | server: $(cat "$WORK/iperf3-server.log")"
  sleep 0.5
done
grep -Eq '[0-9.]+ (M|G)bits/sec' <<<"$out" || fail "iperf3 run has no throughput line: $out"
thruput="$(grep -E '[0-9.]+ (M|G)bits/sec' <<<"$out" | tail -1 | sed 's/^ *//')"
ok "iperf3 localhost throughput run ($thruput)"
iperf3_server_cleanup

# --- socket tables (netstat/lsof -i-lite) ---
out="$("$HOST" sockets --listen)"
echo "$out" | python3 -c "
import json,sys
socks=json.load(sys.stdin)
assert any(s['state']=='LISTEN' for s in socks), socks
assert all(':' in s['local'] or s['proto']=='unix' for s in socks), socks
print('sockets --listen:', len(socks), 'rows, at least one LISTEN')
"
ok "sockets --listen: LISTEN rows with endpoints"

out="$("$HOST" sockets unix)"
echo "$out" | python3 -c "
import json,sys
socks=json.load(sys.stdin)
assert all(s['proto']=='unix' for s in socks), socks
print('sockets unix:', len(socks), 'rows')
"
ok "sockets unix: proto filter honored"

set +e; "$HOST" sockets bogus > /dev/null 2>&1; code=$?; set -e
[ "$code" = 2 ] || fail "sockets with a bogus filter exits 2 (got $code)"
ok "sockets with unknown filter refused (exit 2)"

cat >> "$WORK/smoke.lms" <<'EOF2'
EOF2
cat > "$WORK/socks.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
let socks = net.sockets("tcp", true);
let listeners = 0;
for (i in range(0, socks.len())) {
  let s = socks.at(i);
  if (s.state() == "LISTEN") { listeners = listeners + 1; }
}
println("tcp listeners: " + str(listeners));
if (listeners < 1) { println("no listeners found"); }
end _dsl_
savedsl(p, "$WORK/socks.dslb");
EOF
"$LMSCRIPT" "$WORK/socks.lms" "$WORK/socks.dslb" >/dev/null || fail "socks compile"
out="$("$HOST" --dsl "$WORK/socks.dslb")"
grep -q '^tcp listeners: [1-9]' <<<"$out" || fail "sockets bytecode: $out"
ok "bytecode: net.sockets through the DSL"

# --- socket summary (ss -s-lite) ---
# The table tests above rely on ambient listeners; the summary asserts real
# counts, so pin one deterministic TCP listener on a fixed loopback port
# (15354; the fake DNS server owns 15353).
cat > "$WORK/socksum-server.py" <<'PY'
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 15354))
s.listen(1)
time.sleep(60)
PY
python3 "$WORK/socksum-server.py" &
SUMMARY_SRV_PID=$!
for _ in $(seq 1 25); do
  if out="$("$HOST" sockets --summary 2>/dev/null)"; then break; fi
  sleep 0.2
done
[ -n "$out" ] || fail "sockets --summary produced no output"
SUM_OUT="$out" python3 - <<'PY'
import json, os
s = json.loads(os.environ["SUM_OUT"])  # strict: must be valid JSON
assert isinstance(s["total"], int) and s["total"] >= 1, s
assert s["tcp_states"].get("LISTEN", 0) >= 1, s
assert s["tcp"] + s["tcp6"] + s["udp"] + s["udp6"] + s["unix"] <= s["total"], s
assert s["listening"] >= 1, s
for key in ("tcp", "tcp6", "udp", "udp6", "unix", "listening"):
    assert isinstance(s[key], int) and s[key] >= 0, (key, s)
assert isinstance(s["tcp_states"], dict), s
print("sockets --summary:", s["total"], "sockets,",
      s["listening"], "listening,", len(s["tcp_states"]), "tcp states")
PY
ok "sockets --summary: ss -s-style aggregate with LISTEN state"
ALL_SUM="$out"

out="$("$HOST" sockets tcp --summary)"
TCP_SUM_OUT="$out" SUM_TOTAL="$ALL_SUM" python3 - <<'PY'
import json, os
s = json.loads(os.environ["TCP_SUM_OUT"])
all_s = json.loads(os.environ["SUM_TOTAL"])
assert s["total"] <= all_s["total"], (s, all_s)
assert isinstance(s["tcp6"], int), s  # v6 still reported under a tcp filter
assert s["unix"] == 0, s              # filter excludes unix from every count
print("sockets tcp --summary:", s["total"], "of", all_s["total"], "sockets")
PY
ok "sockets tcp --summary: proto filter honored"

cat > "$WORK/socksum.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
let s = net.socket_summary("");
println("summary: total=" + str(s.total()) + " listen=" + str(s.listening()));
end _dsl_
savedsl(p, "$WORK/socksum.dslb");
EOF
"$LMSCRIPT" "$WORK/socksum.lms" "$WORK/socksum.dslb" >/dev/null || fail "socksum compile"
out="$("$HOST" --dsl "$WORK/socksum.dslb")"
SOCKSUM_OUT="$out" python3 - <<'PY'
import os, re
line = next((l for l in os.environ["SOCKSUM_OUT"].splitlines()
             if re.match(r'^summary: total=[0-9]+ listen=[0-9]+$', l)), None)
assert line is not None, os.environ["SOCKSUM_OUT"]
listen = int(line.rsplit("listen=", 1)[1])
assert listen >= 1, line
print("socksum bytecode:", line)
PY
ok "bytecode: net.socket_summary through the DSL"
kill "$SUMMARY_SRV_PID" 2>/dev/null || true
SUMMARY_SRV_PID=""

# --- scan subcommand (TCP connect port scanner; nmap-lite) ---
# Deterministic on loopback: pin one TCP listener on 127.0.0.1:15355 and
# compare its verdict against a definitely-closed port (15356 refused).
# 15353 belongs to the fake DNS server (UDP), 15354 to the summary listener.
cat > "$WORK/scan-server.py" <<'PY'
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 15355))
s.listen(5)
end = time.time() + 60
while time.time() < end:
    s.settimeout(1)
    try:
        conn, _ = s.accept()
        conn.close()  # answer probes so the accept queue never fills
    except socket.timeout:
        pass
PY
python3 "$WORK/scan-server.py" &
SCAN_SRV_PID=$!
for _ in $(seq 1 25); do
  if "$HOST" scan 127.0.0.1 --ports 15355 --timeout 200 2>/dev/null |
     grep -q '"state":"open"'; then break; fi
  sleep 0.2
done

out="$("$HOST" scan 127.0.0.1 --ports 15355,15356 --timeout 500)"
SCAN_OUT="$out" python3 - <<'PY'
import json, os
r = json.loads(os.environ["SCAN_OUT"])  # strict: must be valid JSON
assert r["host"] == "127.0.0.1", r
assert r["resolved"] == "127.0.0.1", r
assert r["open"] == 1 and r["closed"] == 1 and r["filtered"] == 0, r
by_port = {p["port"]: p for p in r["ports"]}
assert set(by_port) == {15355, 15356}, r
assert by_port[15355]["state"] == "open", r
assert by_port[15355]["service"] == "", r  # 15355 has no well-known name
assert by_port[15356]["state"] == "closed", r
print("scan:", r["open"], "open,", r["closed"], "closed,", r["filtered"], "filtered")
PY
ok "scan: loopback open/closed verdicts with service names"

out="$("$HOST" scan 127.0.0.1 --timeout 200)"
DEF_SCAN_OUT="$out" python3 - <<'PY'
import json, os
r = json.loads(os.environ["DEF_SCAN_OUT"])  # strict: must be valid JSON
top15 = {22, 53, 80, 110, 143, 443, 465, 587, 993, 995,
         3306, 5432, 6379, 8080, 8443}
scanned = {p["port"] for p in r["ports"]}
open_ports = {p["port"] for p in r["ports"] if p["state"] == "open"}
assert scanned == top15, r  # default spec is exactly the built-in top-15
assert len(r["ports"]) == 15, r
assert r["open"] + r["closed"] + r["filtered"] == 15, r
assert open_ports <= top15, r
print("scan default top-15: open ports:", sorted(open_ports))
PY
ok "scan: default top-15 ports, counts sum to 15"

# .invalid is RFC-2606 guaranteed NXDOMAIN, so this stays offline-safe; a
# sandbox without DNS at all still fails resolution, which is the assertion.
set +e; "$HOST" scan nonexistent-hostname-for-lmnet-test.invalid --timeout 200 \
  >"$WORK/scan-dns.out" 2>"$WORK/scan-dns.err"; code=$?; set -e
[ "$code" = 1 ] || fail "scan unresolvable host exits 1 (got $code): $(cat "$WORK/scan-dns.out")"
[ -s "$WORK/scan-dns.err" ] || fail "scan resolution failure writes stderr"
grep -q 'lmnet scan' "$WORK/scan-dns.err" || \
  fail "scan error names the tool: $(cat "$WORK/scan-dns.err")"
ok "scan failure exits 1 with 'lmnet scan' on stderr"

set +e
"$HOST" scan 127.0.0.1 --ports banana >/dev/null 2>&1; c1=$?
"$HOST" scan 127.0.0.1 --ports 0 >/dev/null 2>&1; c2=$?
"$HOST" scan 127.0.0.1 --ports 70000 >/dev/null 2>&1; c3=$?
set -e
{ [ "$c1" = 2 ] && [ "$c2" = 2 ] && [ "$c3" = 2 ]; } || \
  fail "bad --ports specs must exit 2 (banana=$c1 zero=$c2 70000=$c3)"
ok "scan rejects bad port specs (exit 2)"

cat > "$WORK/sockscan.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
println("check open: " + str(net.check("127.0.0.1", 15355)));
println("check closed: " + str(net.check("127.0.0.1", 15356)));
let r = net.scan("127.0.0.1", "15355");
println("scan open=" + str(r.open()));
println("scan resolved=" + r.resolved());
end _dsl_
savedsl(p, "$WORK/sockscan.dslb");
EOF
"$LMSCRIPT" "$WORK/sockscan.lms" "$WORK/sockscan.dslb" >/dev/null || fail "sockscan compile"
out="$("$HOST" --dsl "$WORK/sockscan.dslb")"
grep -q '^check open: true$' <<<"$out" || fail "net.check open port: $out"
grep -q '^check closed: false$' <<<"$out" || fail "net.check closed port: $out"
grep -q '^scan open=1$' <<<"$out" || fail "net.scan open count: $out"
grep -q '^scan resolved=127\.0\.0\.1$' <<<"$out" || fail "net.scan resolved: $out"
ok "bytecode: net.check + net.scan through the DSL"
kill "$SCAN_SRV_PID" 2>/dev/null || true
SCAN_SRV_PID=""

# --- route subcommand (rtnetlink dump, ip route-lite) ---
out="$("$HOST" route)"
ROUTE_OUT="$out" python3 - <<'PY'
import json, os
routes = json.loads(os.environ["ROUTE_OUT"])  # strict: must be valid JSON
assert len(routes) >= 1, routes
assert all(r["dest"] and r["proto"] for r in routes), routes
assert {r["table"] for r in routes}, routes  # table names/numbers present
for r in routes:  # a default route is only usable with a gateway or device
    if r["dest"] == "default":
        assert r["via"] or r["dev"], r
print("route:", len(routes), "routes, tables:", ",".join(sorted({r['table'] for r in routes})))
PY
ok "route: JSON dump with dest/proto on every route, sane default routes"

cat > "$WORK/routes.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
let routes = net.routes();
println("routes: " + str(routes.len()));
let r = routes.at(0);
println("first: " + r.dest() + " proto=" + r.proto() + " table=" + r.table());
end _dsl_
savedsl(p, "$WORK/routes.dslb");
EOF
"$LMSCRIPT" "$WORK/routes.lms" "$WORK/routes.dslb" >/dev/null || fail "routes compile"
out="$("$HOST" --dsl "$WORK/routes.dslb")"
grep -q '^routes: [1-9]' <<<"$out" || fail "routes bytecode count: $out"
grep -q '^first: .*proto=' <<<"$out" || fail "routes bytecode first route: $out"
ok "bytecode: net.routes through the DSL"

cat > "$WORK/routeoob.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
net.routes().at(9999);
end _dsl_
savedsl(p, "$WORK/routeoob.dslb");
EOF
"$LMSCRIPT" "$WORK/routeoob.lms" "$WORK/routeoob.dslb" >/dev/null || fail "compile"
set +e; out="$("$HOST" --dsl "$WORK/routeoob.dslb" 2>&1)"; code=$?; set -e
[ "$code" = 3 ] && [[ "$out" == *'out of range'* ]] || fail "RouteList.at bounds (exit $code): $out"
ok "RouteList.at out of range refused (exit 3)"

# --- neigh subcommand (rtnetlink dump, ip neigh/arp-lite) ---
# Offline-deterministic: a fresh CI box may have an empty table, so nothing
# here asserts a neighbor exists; only shape and invariants are checked.
out="$("$HOST" neigh)"
NEIGH_OUT="$out" python3 - <<'PY'
import json, os
neighs = json.loads(os.environ["NEIGH_OUT"])  # strict: must be valid JSON
for n in neighs:
    assert n["ip"] and n["dev"] and n["state"], n
    assert n["family"] in ("ipv4", "ipv6"), n
    assert set(n) == {"ip", "dev", "state", "mac", "family", "router", "proxy"}, n
print("neigh:", len(neighs), "entries")
PY
ok "neigh: JSON dump, ip/dev/state/family on every entry"

cat > "$WORK/neigh.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
let neighs = net.neighbors();
println("neighbors: " + str(neighs.len()));
if (neighs.len() > 0) {
  let n = neighs.at(0);
  println("first: " + n.ip() + " dev " + n.dev() + " state " + n.state());
}
end _dsl_
savedsl(p, "$WORK/neigh.dslb");
EOF
"$LMSCRIPT" "$WORK/neigh.lms" "$WORK/neigh.dslb" >/dev/null || fail "neigh compile"
out="$("$HOST" --dsl "$WORK/neigh.dslb")"
grep -Eq '^neighbors: [0-9]+$' <<<"$out" || fail "neigh bytecode count: $out"
ok "bytecode: net.neighbors through the DSL"

cat > "$WORK/neighoob.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
net.neighbors().at(9999);
end _dsl_
savedsl(p, "$WORK/neighoob.dslb");
EOF
"$LMSCRIPT" "$WORK/neighoob.lms" "$WORK/neighoob.dslb" >/dev/null || fail "compile"
set +e; out="$("$HOST" --dsl "$WORK/neighoob.dslb" 2>&1)"; code=$?; set -e
[ "$code" = 3 ] && [[ "$out" == *'out of range'* ]] || fail "NeighborList.at bounds (exit $code): $out"
ok "NeighborList.at out of range refused (exit 3)"

# --- link subcommand (rtnetlink dump, ip -s link-lite) ---
# Offline-deterministic: the loopback link always exists, so lo is asserted.
out="$("$HOST" link)"
LINK_OUT="$out" python3 - <<'PY'
import json, os
links = json.loads(os.environ["LINK_OUT"])  # strict: must be valid JSON
assert len(links) >= 1, links
lo = [l for l in links if l["name"] == "lo"]
assert len(lo) == 1, links
assert lo[0]["up"] is True and lo[0]["loopback"] is True, lo[0]
for l in links:
    assert l["name"] and isinstance(l["mtu"], int) and l["mtu"] >= 0, l
    for k in ("rx_bytes", "rx_packets", "rx_errors", "rx_dropped",
              "tx_bytes", "tx_packets", "tx_errors", "tx_dropped"):
        assert isinstance(l[k], int) and l[k] >= 0, (k, l)
print("link:", len(links), "devices, lo up/loopback, counters sane")
PY
ok "link: JSON dump, lo up/loopback, non-negative counters everywhere"

cat > "$WORK/links.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
let links = net.links();
println("links: " + str(links.len()));
for (i in range(0, links.len())) {
  let l = links.at(i);
  if (l.name() == "lo") { println("lo: up " + str(l.up()) + " mtu=" + str(l.mtu())); }
}
end _dsl_
savedsl(p, "$WORK/links.dslb");
EOF
"$LMSCRIPT" "$WORK/links.lms" "$WORK/links.dslb" >/dev/null || fail "links compile"
out="$("$HOST" --dsl "$WORK/links.dslb")"
grep -q '^links: [1-9]' <<<"$out" || fail "links bytecode count: $out"
grep -q '^lo: up true mtu=' <<<"$out" || fail "links bytecode lo line: $out"
ok "bytecode: net.links through the DSL"

cat > "$WORK/linkoob.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
net.links().at(9999);
end _dsl_
savedsl(p, "$WORK/linkoob.dslb");
EOF
"$LMSCRIPT" "$WORK/linkoob.lms" "$WORK/linkoob.dslb" >/dev/null || fail "compile"
set +e; out="$("$HOST" --dsl "$WORK/linkoob.dslb" 2>&1)"; code=$?; set -e
[ "$code" = 3 ] && [[ "$out" == *'out of range'* ]] || fail "LinkList.at bounds (exit $code): $out"
ok "LinkList.at out of range refused (exit 3)"

# --- counters subcommand (/proc/net/{snmp,netstat,snmp6}, netstat -s/nstat-lite) ---
# Offline-deterministic: /proc/net/snmp always exists on Linux; a missing
# /proc/net/snmp6 (or netstat) degrades silently, so only shape and
# invariants are checked. Tcp.MaxConn is -1 on real kernels (kernel
# convention for "no global limit"), the one documented non-counter field.
out="$("$HOST" counters)"
COUNTERS_OUT="$out" python3 - <<'PY'
import json, os, re
counters = json.loads(os.environ["COUNTERS_OUT"])  # strict: must be valid JSON
assert isinstance(counters, dict), type(counters)
assert len(counters) >= 50, len(counters)
for key in ("Ip.InReceives", "Tcp.ActiveOpens", "Udp.InDatagrams"):
    assert key in counters, key
name = re.compile(r'^[A-Za-z0-9_.]+$')
for key, value in counters.items():
    assert name.match(key), key
    assert isinstance(value, int), (key, value)
    assert value >= 0 or key == "Tcp.MaxConn", (key, value)
print("counters:", len(counters), "keys, Ip/Tcp/Udp spot keys, names sane")
PY
ok "counters: JSON object, >=50 keys, Ip/Tcp/Udp spot keys, names sane"

cat > "$WORK/counters.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
let cs = net.counters();
println("counters: " + str(cs.len()));
for (i in range(0, cs.len())) {
  let c = cs.at(i);
  if (c.name() == "Ip.InReceives") { println("ip receives: " + str(c.value())); }
}
end _dsl_
savedsl(p, "$WORK/counters.dslb");
EOF
"$LMSCRIPT" "$WORK/counters.lms" "$WORK/counters.dslb" >/dev/null || fail "counters compile"
out="$("$HOST" --dsl "$WORK/counters.dslb")"
grep -q '^counters: [1-9][0-9]' <<<"$out" || fail "counters bytecode count: $out"
grep -q '^ip receives: [0-9][0-9]*$' <<<"$out" || fail "counters bytecode ip receives: $out"
ok "bytecode: net.counters through the DSL"

cat > "$WORK/countersoob.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
net.counters().at(999999);
end _dsl_
savedsl(p, "$WORK/countersoob.dslb");
EOF
"$LMSCRIPT" "$WORK/countersoob.lms" "$WORK/countersoob.dslb" >/dev/null || fail "compile"
set +e; out="$("$HOST" --dsl "$WORK/countersoob.dslb" 2>&1)"; code=$?; set -e
[ "$code" = 3 ] && [[ "$out" == *'out of range'* ]] || fail "CounterList.at bounds (exit $code): $out"
ok "CounterList.at out of range refused (exit 3)"

# --- rule subcommand (rtnetlink dump, ip rule-lite) ---
# Offline-deterministic: every Linux kernel ships the local+main rules, so
# the pref-0 local lookup rule is asserted.
out="$("$HOST" rule)"
RULE_OUT="$out" python3 - <<'PY'
import json, os, re
rules = json.loads(os.environ["RULE_OUT"])  # strict: must be valid JSON
assert len(rules) >= 1, rules
assert any(r["pref"] == 0 and r["action"] == "lookup" and r["table"] == "local"
           for r in rules), rules
cidr = re.compile(r'^\S+/\d+$')
fwmark = re.compile(r'^0x[0-9a-fA-F]+(/0x[0-9a-fA-F]+)?$')
for r in rules:
    assert r["action"] and r["table"], r
    if r["from"]: assert cidr.match(r["from"]), r
    if r["fwmark"]: assert fwmark.match(r["fwmark"]), r
print("rule:", len(rules), "rules, pref-0 local lookup present")
PY
ok "rule: JSON dump, pref-0 local lookup, sane action/table/from/fwmark"

cat > "$WORK/rules.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
let rules = net.rules();
println("rules: " + str(rules.len()));
for (i in range(0, rules.len())) {
  let r = rules.at(i);
  if (r.pref() == 0) {
    if (r.table() == "local") { println("local rule found"); }
  }
}
end _dsl_
savedsl(p, "$WORK/rules.dslb");
EOF
"$LMSCRIPT" "$WORK/rules.lms" "$WORK/rules.dslb" >/dev/null || fail "rules compile"
out="$("$HOST" --dsl "$WORK/rules.dslb")"
grep -q '^rules: [1-9]' <<<"$out" || fail "rules bytecode count: $out"
grep -q '^local rule found$' <<<"$out" || fail "rules bytecode local rule: $out"
ok "bytecode: net.rules through the DSL"

cat > "$WORK/ruleoob.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
net.rules().at(9999);
end _dsl_
savedsl(p, "$WORK/ruleoob.dslb");
EOF
"$LMSCRIPT" "$WORK/ruleoob.lms" "$WORK/ruleoob.dslb" >/dev/null || fail "compile"
set +e; out="$("$HOST" --dsl "$WORK/ruleoob.dslb" 2>&1)"; code=$?; set -e
[ "$code" = 3 ] && [[ "$out" == *'out of range'* ]] || fail "RuleList.at bounds (exit $code): $out"
ok "RuleList.at out of range refused (exit 3)"

# --- trace subcommand (UDP probes + ICMP answers; needs CAP_NET_RAW, skip without) ---
set +e; out="$("$HOST" trace 127.0.0.1 2>&1)"; code=$?; set -e
TRACE_RAW=0
if [ "$code" = 0 ]; then
  TRACE_RAW=1
  echo "$out" | python3 -c "
import json,sys
r=json.load(sys.stdin)  # strict: must be valid JSON
assert r['dest_ip']=='127.0.0.1', r
assert len(r['hops'])==1, r  # loopback: the ttl=1 probe already reaches
h=r['hops'][0]
assert h['ttl']==1 and h['from']=='127.0.0.1' and h['reached'] is True, r
assert h['rtt_ms']>=0, r
print('trace 127.0.0.1: 1 hop, reached, rtt %.3f ms' % h['rtt_ms'])
"
  ok "trace 127.0.0.1: loopback reached on hop 1"
elif echo "$out" | grep -qi 'CAP_NET_RAW\|operation not permitted\|permission denied'; then
  echo "ok $((++pass)) - trace skipped: no raw-socket permission in this environment"
else
  fail "trace 127.0.0.1 failed (exit $code): $out"
fi

set +e; "$HOST" trace nonexistent.invalid-lmnet-test. >/dev/null 2>"$WORK/trace.err"; code=$?; set -e
[ "$code" = 1 ] || fail "trace unresolvable host exits 1 (got $code)"
grep -qi 'nonexistent.invalid-lmnet-test' "$WORK/trace.err" || \
  fail "trace error names the host: $(cat "$WORK/trace.err")"
ok "trace failure exits 1 naming the host"

# Failed traces are data in the DSL (error() carries the message), so the same
# bytecode runs cleanly with and without raw-socket permission.
cat > "$WORK/trace.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
let r = net.trace("127.0.0.1", 8);
if (r.error() != "") {
  println("trace unavailable: " + r.error());
} else {
  println("dest: " + r.dest_ip());
  println("hops: " + str(r.hops().len()));
  println("reached: " + str(r.hops().at(0).reached()));
}
end _dsl_
savedsl(p, "$WORK/trace.dslb");
EOF
"$LMSCRIPT" "$WORK/trace.lms" "$WORK/trace.dslb" >/dev/null || fail "trace compile"
out="$("$HOST" --dsl "$WORK/trace.dslb")"
if [ "$TRACE_RAW" = 1 ]; then
  grep -q '^dest: 127\.0\.0\.1$' <<<"$out" || fail "trace bytecode dest: $out"
  grep -q '^hops: 1$' <<<"$out" || fail "trace bytecode hops: $out"
  grep -q '^reached: true$' <<<"$out" || fail "trace bytecode reached: $out"
  ok "bytecode: net.trace through the DSL"
else
  grep -q '^trace unavailable:' <<<"$out" || fail "trace bytecode error branch: $out"
  echo "ok $((++pass)) - bytecode trace skipped: no raw-socket permission (error branch verified)"
fi

# Bounds refusal needs no socket: a permission failure yields an empty hop
# list, so at(999) is still out of range everywhere.
cat > "$WORK/traceoob.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
net.trace("127.0.0.1", 8).hops().at(999);
end _dsl_
savedsl(p, "$WORK/traceoob.dslb");
EOF
"$LMSCRIPT" "$WORK/traceoob.lms" "$WORK/traceoob.dslb" >/dev/null || fail "compile"
set +e; out="$("$HOST" --dsl "$WORK/traceoob.dslb" 2>&1)"; code=$?; set -e
[ "$code" = 3 ] && [[ "$out" == *'out of range'* ]] || fail "HopList.at bounds (exit $code): $out"
ok "HopList.at out of range refused (exit 3)"

# --- DSL bytecode ---
cat > "$WORK/smoke.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
let addrs = net.dns_lookup("localhost");
if (addrs.len() < 1) { println("no addresses"); }
println("localhost -> " + str(addrs.len()) + " addresses");
let ifs = net.interfaces();
let names = str_list();
for (i in range(0, ifs.len())) {
  let f = ifs.at(i);
  println(f.name() + " " + f.addr() + " mtu=" + str(f.mtu()));
  if (f.loopback()) { names.add("lo-present"); }
}
if (names.len() != 1) { println("missing loopback"); }
end _dsl_
savedsl(p, "$WORK/smoke.dslb");
EOF
"$LMSCRIPT" "$WORK/smoke.lms" "$WORK/smoke.dslb" >/dev/null || fail "smoke compile"
[ "$(od -An -t u1 -j 5 -N 1 "$WORK/smoke.dslb" | tr -d ' ')" = 5 ] || fail "smoke was not compiled as bytecode v5"
out="$("$HOST" --dsl "$WORK/smoke.dslb")"
[ "$(tail -1 <<<"$out")" = '{"ok": true, "result": null}' ] || fail "smoke run: $out"
grep -q '^localhost -> [1-9]' <<<"$out" || fail "smoke dns line: $out"
grep -q 'lo 127\.0\.0\.1/8 mtu=' <<<"$out" || grep -q 'lo ::1/128 mtu=' <<<"$out" || fail "smoke interfaces line: $out"
ok "bytecode: dns_lookup + interfaces through the DSL"

cat > "$WORK/oob.lms" <<EOF
p = _dsl_ cli="lmnet" install="github:lmctl-ai/lmnet@latest";
net.interfaces().at(99);
end _dsl_
savedsl(p, "$WORK/oob.dslb");
EOF
"$LMSCRIPT" "$WORK/oob.lms" "$WORK/oob.dslb" >/dev/null || fail "compile"
set +e; out="$("$HOST" --dsl "$WORK/oob.dslb" 2>&1)"; code=$?; set -e
[ "$code" = 3 ] && [[ "$out" == *'out of range'* ]] || fail "IfaceList.at bounds (exit $code): $out"
ok "IfaceList.at out of range refused (exit 3)"

set +e; out="$("$HOST" 2>&1)"; code=$?; set -e
[ "$code" = 2 ] && [[ "$out" == *'usage: lmnet'* ]] || fail "bad args refusal (exit $code): $out"
ok "bad arguments refused (exit 2)"
set +e; out="$("$HOST" --dsl "$WORK/no-such.dslb" 2>&1)"; code=$?; set -e
[ "$code" = 3 ] && [[ "$out" == *'"phase": "load"'* ]] || fail "missing bytecode refusal (exit $code): $out"
ok "missing bytecode file refused at load (exit 3)"

"$HOST" --dsl "$WORK/smoke.dslb" "$WORK/smoke.dslb" >"$WORK/multi.jsonl" || fail "multi-bytecode run"
[ "$(grep -c '^{"ok"' "$WORK/multi.jsonl" | tr -d ' ')" = 2 ] || fail "multiple bytecode files did not run in order"
ok "multiple bytecode files run sequentially"

# --- examples compile and run ---
mkdir -p build
for f in counters dns-lookup dns-query interfaces link neigh routes rule scan sockets sockets-summary trace; do
  [ -f "examples/$f.lms" ] || continue
  "$LMSCRIPT" "examples/$f.lms" "build/$f.dslb" >"$WORK/$f.compile.log" 2>&1 || fail "$f example compile"
  "$HOST" --dsl "build/$f.dslb" >"$WORK/$f.out" || fail "$f example run"
  while IFS= read -r line; do
    grep -qxF "${line:2}" "$WORK/$f.out" || fail "$f example output missing: ${line:2} (got $(cat "$WORK/$f.out"))"
  done < <(grep '^#|' "examples/$f.lms")
done
ok "examples compile and their expected output matches"

LDD_OUT="$(ldd "$HOST" 2>&1 || true)"
[[ "$LDD_OUT" == *'not a dynamic executable'* ]] || fail "host is not fully static: $LDD_OUT"
ok "host is fully static ($(stat_size "$HOST") bytes, ldd clean)"

# The published compiler injects std; the host embeds only its own schema bytes.
"$LMSCRIPT" --dsl-signatures schema/lmnet.dsl.json --without-std > "$WORK/std-host-only.sig"
"$LMSCRIPT" --dsl-signatures cpp/std/lmcode-std.schema.json > "$WORK/std-builtins.sig"
"$HOST" --dsl-signatures > "$WORK/std-registry.sig"
python3 - "$WORK" <<'PYSTD'
import pathlib,sys,json
w=pathlib.Path(sys.argv[1])
read=lambda name:set((w/name).read_text().splitlines())
assert read('std-registry.sig')-read('std-builtins.sig') == read('std-host-only.sig'), 'host-only registry drift'
schema=str(pathlib.Path('schema/lmnet.dsl.json').resolve()).replace('\\','/')
out=str(w/'std-probe.dslb').replace('\\','/')
(w/'std-probe.lms').write_text('p = _lmcode_ schema='+json.dumps(schema)+';\nlet values = str_list().add("abc");\nif (str_len(values.at(0)) != 3) { let bad = int_list().at(0); }\nend _lmcode_\nsavedsl(p, '+json.dumps(out)+');\n')
PYSTD
"$LMSCRIPT" "$WORK/std-probe.lms" > "$WORK/std-probe.log" 2>&1 || { cat "$WORK/std-probe.log"; fail "implicit std compile"; }
"$HOST" --dsl "$WORK/std-probe.dslb" > "$WORK/std-run.log" 2>&1 || { cat "$WORK/std-run.log"; fail "implicit std runtime"; }
ok "host-only signatures and implicit std runtime"

echo "PASS: $pass checks"
