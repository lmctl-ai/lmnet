#!/usr/bin/env bash
# Download the pinned iputils source tarball and unpack it into third_party/iputils.
set -eu
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$HERE/iputils.lock"
DEST="$HERE/third_party/iputils"
URL="$(sed -n 's/^repo=//p' "$LOCK")"
WANT="$(sed -n 's/^sha256=//p' "$LOCK")"

if [ "${1:-}" = "--verify" ]; then
  [ -f "$DEST/LICENSE" ] || { echo "third_party/iputils missing: run scripts/sync-iputils.sh" >&2; exit 1; }
  grep -q "arping: GPL-2.0-or-later" "$DEST/LICENSE" 2>/dev/null \
    || { echo "third_party/iputils does not look like the pinned iputils release" >&2; exit 1; }
  echo "third_party/iputils present (sha256 $WANT)"
  exit 0
fi

[ -n "$WANT" ] || { echo "sha256 missing in $LOCK" >&2; exit 1; }
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lmnet-iputils-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
echo "fetching $URL"
curl -fL "$URL" -o "$WORK/iputils.tar.gz"
HAVE="$(sha256sum "$WORK/iputils.tar.gz" | cut -c1-64)"
[ "$HAVE" = "$WANT" ] || { echo "sha256 $HAVE differs from iputils.lock $WANT" >&2; exit 1; }
rm -rf "$DEST"
mkdir -p "$DEST"
tar xzf "$WORK/iputils.tar.gz" -C "$DEST" --strip-components=1
echo "unpacked iputils into $DEST (sha256 verified)"
