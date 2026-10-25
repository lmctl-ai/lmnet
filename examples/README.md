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
- `interfaces.lms` — enumerate interfaces, addresses, MTUs and flags

`./test.sh` compiles and runs every example as part of the check suite.
