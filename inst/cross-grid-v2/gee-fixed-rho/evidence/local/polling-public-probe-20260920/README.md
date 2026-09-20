# Local public polling attribution — 2026-09-20

This is a local macOS public-payload microbenchmark, not a pod4, exactGC, DP
release, correctness or capacity proof. It launched two new temporary callr
workers and closed them. It used no existing sessions or protected data and
made no source/default changes. The process exited zero.

The retained script loads the existing `DSVertE2EProcessConnection` connector,
registers an isolated public echo RPC, and invokes the real
`.dsvert_dsi_direct_aggregate` with its expression-size guard. This follows the
release relay's direct-dispatch implementation and records requested/actual
polling sleeps through the existing injectable `.sleep` argument. Each public
payload has 655,360 base64 characters, the length for a 480 KiB raw chunk. It
omits exactGC authentication, encryption, durable spools, actual release
allowlists and DP computation. Request/response shapes are simplified echo
records; these timings do not predict real release throughput.

Three alternating repetitions compare the default polling intervals
(.05, 1, 2 seconds) with (.005, .01, .02 seconds) for the `.0`, `.1`, `.10`
options. A tiny two-peer control call, full upload, full download, and calls
with explicit 55 ms / 1.01 s worker delays are retained individually.

| Case | Default mean seconds | Short polling mean seconds |
|---|---:|---:|
| Two-peer tiny control | 0.1057 | 0.0380 |
| Full upload | 0.2913 | 0.2650 |
| Full download | 0.0600 | 0.0400 |
| Explicit 55 ms work | 0.1187 | 0.1003 |
| Explicit 1.01 s work | 1.0907 | 1.0523 |

The sum of measured upload/download means fell from 0.3513 to 0.3050 seconds,
about 13%. This is an arithmetic sum of two separately measured calls, not a
measured authenticated relay cycle. Full-upload expression validation alone
averaged about 0.105 seconds. Total sleeping overlaps worker execution and
must not be counted as wholly removable overhead. No one-second sleep occurred
in this run: observed maximum requested sleeps were .05 and .005 seconds.

The source explains why missing the first 50 ms poll does not immediately
cause a one-second sleep. `checks` starts at 1 for every aggregate; the first
threshold is `1 / t0`, hence check 20 at the default .05-second setting.
Checks 1–19 keep using .05 seconds. Short polling may lower response latency
but increases polling work; this microbenchmark provides no evidence for a
10-fold bulk-throughput improvement. No production default was changed.

A separate static audit found no per-frame full runtime-binary rehash in the
proof's explicit `dsvert.mpc_binary` path. Runtime compatibility is cached by
filesystem identity; packaged-file checksum validation also has a stamp cache.
Each newly emitted exactGC envelope does call native `derive-identity` and
`sign-transport`, and each delivery calls `verify-transport`; each invocation
uses private-file JSON I/O, a new process, and file cleanup. Their latency was
not measured here. The exactGC source-frame path also repeatedly enumerates,
parses and stats the outbound segment directory, and verifies each selected
segment hash before reading its chunk. These are candidates for separate
attribution, not established causes of the observed pod relay rate.

`results.json` binds the exact local dispatcher source hash and contains all
30 measured calls. `probe.log` is the unmodified successful process output;
`probe.R` is the executed source. `provenance.json` records the local platform
and explicit nonrelease scope. `SHA256SUMS` covers these retained files.
