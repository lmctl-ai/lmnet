# Third-Party Notices

## iputils

This repository builds against, and includes verbatim source files from,
**iputils** — a set of small useful utilities for Linux networking.

- Upstream: https://github.com/iputils/iputils
- Version: 20250605, pinned in `iputils.lock`
- Copyright (C) various authors; see the vendored `LICENSE` file at
  `third_party/iputils/LICENSE` after running `scripts/sync-iputils.sh`
- Per-tool licenses (from the upstream LICENSE file):
  - `ping`: **BSD-3-Clause**
  - `tracepath`: **GPL-2.0-or-later**
  - (`arping`: GPL-2.0-or-later and `clockdiff`: BSD-3-Clause are vendored
    with the tarball but not compiled into lmnet)

The MIT license (see `LICENSE`) applies only to files authored for lmnet;
iputils source files remain under their upstream licenses. Because the
compiled lmnet executable links iputils object code, that executable is a
combined work distributed under the terms covering the included tools.

## lmcode-cpp SDK

`cpp/dslvm.hpp`, `cpp/stdlib/*.hpp`, `cpp/std/lmcode-std.schema.json` and
`scripts/merge-std.py` are vendored from lmcode-cpp (MIT License, Lattice
Systems LLC), pinned by `sdk.lock` and synced by `scripts/sync-sdk.sh`.
