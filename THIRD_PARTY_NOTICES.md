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

## iperf3

This repository builds against, and includes verbatim source files from,
**iperf3** — the standard TCP/UDP/SCTP network throughput measurement tool.

- Upstream: https://github.com/esnet/iperf (tarball from https://downloads.es.net/pub/iperf/)
- Version: 3.22, pinned in `iperf3.lock` and synced by `scripts/sync-iperf3.sh`
- Copyright (c) 2014-2023 The Regents of the University of California, through
  Lawrence Berkeley National Laboratory; see the vendored `LICENSE` file at
  `third_party/iperf3/LICENSE` after running `scripts/sync-iperf3.sh`
- License: **BSD-3-Clause** — the vendored LICENSE states the three classic
  BSD redistribution conditions (retain copyright notice, reproduce in
  documentation, no endorsement without permission) and: "THIS SOFTWARE IS
  PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND [...]"
  (BSD-style disclaimer), preceded by the U.S. Dept. of Energy notice.

lmnet compiles the iperf3 engine (with its `main` renamed) into the `lmnet
iperf3` subcommand, built without OpenSSL authentication and without SCTP,
matching iperf's own configure defaults; `cpp/iperf3shim/iperf_config.h` and
`cpp/iperf3shim/version.h` stand in for the headers autotools would generate.

## lmcode-cpp SDK

`cpp/dslvm.hpp`, `cpp/stdlib/*.hpp`, `cpp/std/lmcode-std.schema.json` and
`scripts/merge-std.py` are vendored from lmcode-cpp (MIT License, Lattice
Systems LLC), pinned by `sdk.lock` and synced by `scripts/sync-sdk.sh`.
