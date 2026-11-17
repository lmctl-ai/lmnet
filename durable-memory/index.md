# lmnet schema

The host publishes the exact bytes of its checked-in host declaration source.

Compiler >=0.2.482 resolves std (`lmcode_std_v3`, 226 signatures) from the pinned SDK bundle by default; host schema bytes remain host-only, with full and `--without-std` parity plus a standard-only runtime probe in `test.sh`.

- [11-invocation-envelope.md](11-invocation-envelope.md): framed results, dry passivity and tests.
- [12-std-rest-and-cli-interfaces.md](12-std-rest-and-cli-interfaces.md): `lmcode_std_v3` (226 signatures) standard REST/CLI interfaces (`RestGet`..`RestOptions`, `RestHandler`, `CliCommand`, `CliOption`, `rest_config`, `rest_route`, `rest_serve`, `rest_cli`).
