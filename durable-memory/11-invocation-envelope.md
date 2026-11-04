# lmcode invocation envelope (0.1.1)

SDK lmcode-cpp origin/main 93bddf1; compiler staging 0.2.460. Main loop follows
lmfluid's InvocationResults pattern; native network CLI commands are unchanged.
Metadata validation, load-all-before-execution, select/complete/fail, one terminal
frame. Exit 0 success, 2 lmcode CLI/metadata, 3 load/run, 4 application/output.
Dry metadata and standalone --dry-run load without invoking network/file calls.
A standalone dry flag with real-mode metadata is refused. println diagnostics
inside blocks now use stderr. Structured results alone occupy host stdout.

Tests preserve native commands, loopback fake-DNS/TCP fixtures, vendored tools,
all bounds refusals, expected example text and the fully-static linkage gate.
Private-input capture checks bytecode v6/schema hashes. Multi-file success now
has one frame with two results. Added builder/load-before-effects/dry controls
and occupied-port negative control proving dry does not bind a socket.
Compiled recording shim (spawnv Windows, fork/execv Unix); npm Windows compiler
uses .cmd. Shared lmdraw compiler probe copied with host-name substitution.
The host itself remains Linux-only: iputils, kernel networking and existing CI
are not expanded to other platforms. No renderers or renderer downloads exist.
