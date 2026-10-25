#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
BUILD_DIR="${BUILD_DIR:-build}"
HOST="$BUILD_DIR/lmnet"
stat_size(){ stat -c %s "$1" 2>/dev/null || stat -f%z "$1"; }
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lmnet-test-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
pass=0
ok(){ pass=$((pass+1)); echo "ok $pass - $1"; }
fail(){ echo "FAIL: $*" >&2; exit 1; }

LMSCRIPT="$(scripts/select-compiler.sh)"
COMPILER_SOURCE="$LMSCRIPT"
scripts/sync-sdk.sh --verify >/dev/null || fail "SDK header pin mismatch"
ok "SDK headers match sdk.lock"
scripts/sync-iputils.sh --verify >/dev/null || fail "iputils pin mismatch"
ok "third_party/iputils matches iputils.lock"

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
for t in ('Net','Iface','IfaceList','StrList'):
    assert t in d.get('types',{}), t
print('embedded schema: name lmnet, Net/Iface/IfaceList + std StrList present')
PY
cmp schema/lmnet.dsl.json "$WORK/embedded-schema.json" || fail "embedded schema differs from merged schema bytes"
ok "--dsl-schema --json prints byte-identical merged schema bytes"
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
for f in dns-lookup interfaces; do
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

echo "PASS: $pass checks"
