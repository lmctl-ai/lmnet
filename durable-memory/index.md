# lmnet schema

The host publishes the exact bytes of its checked-in host declaration source.

Compiler >=0.2.460 resolves std from the pinned SDK bundle by default; host schema bytes remain host-only, with full and `--without-std` parity plus a standard-only runtime probe in `test.sh`.

- [11-invocation-envelope.md](11-invocation-envelope.md): framed results, dry passivity and tests.
