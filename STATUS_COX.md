# Cox cross-owner grid status

## 2026-09-18 resumed
The quota interruption left no Cox status/decision files. Inspected both repositories before changes; base server 38146c0 (approved primitive), client cb26ecd. Preserved the untracked Cox files and one additive client NAMESPACE export. No half-written files were discarded.

Recovered: pinned interval-generated exp/log profile; public caps; chunk planner/emitter; server/client signed contract validators; test-tagged Go plaintext command; client API/docs and four tests. Production registration/release deliberately disabled pending authenticated fusion.

Verified on resume: `go test -run '^TestCoxGridCrossProfile' -count=1 -timeout=5m .` passed (4 selected top-level tests; 0.770 s). `devtools::test("dsVertClient", filter="dp-cox-grid-cross", reporter="summary")` passed (4 tests, 36 expectations). Dense exp/log tests are separate names and not included in that initial filter.

Pod readiness checked: /workspace/logs/install_r.log ends R_STACK_DONE. Work uses /workspace/dsvert/cox/.

Remaining: compiled chunk equality/costs, pure R integer oracle, sensitivity neighbours, server contract parity, two-peer synthetic DSLite/coxph comparison, package checks, integration gate report.

## 2026-09-18 resumed — implemented milestones

1. Preserved recovered work: server `dd25445`, client `19b0e02`.
2. Compiled profile equality, signed lower-bound fix, joined f100 rounding/slack,
   carried Breslow ties across 32-row tiles, empty/invalid/censored fixtures,
   canonical schedule tamper rejection, final lattice ties/clamps, encrypted
   forward scan and maximum-shape preflights: server `2f2c547`.
3. Independent pure-R integer risk-set oracle and public cap derivation;
   real-signature fail-closed server validators and integration contract-only
   states: server `1bfe8a5`.
4. Two real DSLite connections and test-tagged Go oracle, R oracle equality,
   epsilon {1,4,8} reference-noise selection, centralized Breslow coxph comparison,
   server/client canonical parity: client `6b993e2`.

Targeted local R checks: 4 server tests / 626 expectations; 5 client contract
and parity tests / 37 expectations; 1 DSLite synthetic test / 23 expectations.
All passed. Initial isolated client-only run intentionally skipped the tagged
fixture until its explicit test binary was supplied. The explicit run passed.

New scalar compiler profile: standard MPCL pruning and array multiplication,
with public shared coefficient-bit decision diagrams. Scalar exp: 4901 gates,
1514 non-XOR, 48432 table bytes. Scalar normalized log: 5253 gates, 1486 non-XOR,
47536 table bytes. Both meet the 2000 non-XOR gate target, and all public
boundary fixtures remain bit-for-bit equal. These counts exclude separate
share joins/output masks. No reference Boolean optimizer was adopted.

The 10000-row, 50-candidate padded schedule has 239700 chunks. Its component-call
model alone contains 819200 evaluations of each scalar, approximately 78.6 GB
of nonlinear tables before permutation, framing, OT and protocol overhead.
Thus scalar-target success does not satisfy the complete 30 GB envelope.
Production remains disabled; see INTEGRATION_COX.md for exact remaining wiring.

Full validation running on pod under /workspace/dsvert/cox:
- GOMAXPROCS=8 go test -run '^TestCoxGridCross' -count=1 -json -timeout=15m .
- GOMAXPROCS=8 go test -count=1 -json -timeout=0 .
- R CMD check --no-manual --no-build-vignettes for both source packages.
- Client check uses _R_CHECK_FORCE_SUGGESTS_=false and the explicit tagged binary.
The readiness marker was present but RSQLite was missing; installed it only in
/workspace/dsvert/cox/rlib. R library and other sessions were not modified.
Final counts/check outcomes will be appended after completion; running checks
are not claimed as passes here.

## 2026-09-18 resumed — final Cox Go gate

Pod final family suite passed: **16 top-level tests + 7 subtests**, no failures
or skips, 657.494 seconds on the shared 96-vCPU Xeon pod (Go 1.25.7,
GOMAXPROCS=8). `inst/cross-cox-v1/validation.json` retains names, command and
log digest; `costs_pod.json` retains measured shapes, source digests and limits.
The tagged Go test executable was rebuilt from the same final source.

Maximal public chunks: prepare 322807 gates, permutation 417399, forward 487688,
backward 140520, finalize 2967. Maximum measured source 71160 bytes, maximum
typed input 53376 bits. All stay below unchanged 32M/2MiB/512Ki-bit runner caps.
Encrypted two-row forward test: 495337 garbler-direction bytes (actual local
secure records/OT); this is not a full authenticated release or inter-host RTT.

The maximum-tile extrapolation for N=10000,J=50 is approximately **722.3 GB table
bytes + 373.0 GB gate-frame bytes**, excluding labels, OT, evaluator traffic,
source transport, PSI, noise and persistence. It is a component-call model, not
an executed full-size release or a certified byte bound. The whole-envelope
cost gate fails despite successful bounded kernels and scalar gate counts.
The expensive repeated permutation reconstruction/remasking and linear scans
must be redesigned/composed more efficiently before production scale admission.
