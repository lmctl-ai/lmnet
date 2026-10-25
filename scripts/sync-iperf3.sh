#!/usr/bin/env bash
# Download the pinned iperf3 source tarball and unpack it into third_party/iperf3.
set -eu
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$HERE/iperf3.lock"
DEST="$HERE/third_party/iperf3"
URL="$(sed -n 's/^repo=//p' "$LOCK")"
WANT="$(sed -n 's/^sha256=//p' "$LOCK")"

if [ "${1:-}" = "--verify" ]; then
  [ -f "$DEST/LICENSE" ] || { echo "third_party/iperf3 missing: run scripts/sync-iperf3.sh" >&2; exit 1; }
  # The 3.22 LICENSE states the BSD redistribution conditions verbatim without
  # naming "BSD"; match its distinctive first condition instead.
  grep -q "Redistribution and use in source and binary forms" "$DEST/LICENSE" 2>/dev/null \
    || { echo "third_party/iperf3 does not look like the pinned iperf3 release" >&2; exit 1; }
  echo "third_party/iperf3 present (sha256 $WANT)"
  exit 0
fi

[ -n "$WANT" ] || { echo "sha256 missing in $LOCK" >&2; exit 1; }
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lmnet-iperf3-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
echo "fetching $URL"
curl -fL "$URL" -o "$WORK/iperf3.tar.gz"
HAVE="$(sha256sum "$WORK/iperf3.tar.gz" | cut -c1-64)"
[ "$HAVE" = "$WANT" ] || { echo "sha256 $HAVE differs from iperf3.lock $WANT" >&2; exit 1; }
rm -rf "$DEST"
mkdir -p "$DEST"
tar xzf "$WORK/iperf3.tar.gz" -C "$DEST" --strip-components=1
echo "unpacked iperf3 into $DEST (sha256 verified)"
