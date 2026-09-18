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

## 2026-09-18 resumed — blocked handoff and check outcomes

See BLOCKED_COX.md. The full release envelope and authenticated fusion remain
unmet, so production admission is disabled and the family session stops.

Both `R CMD check --no-manual --no-build-vignettes` runs successfully installed,
loaded and statically checked the packages and reached `testthat.R`; their test
phases were interrupted after the blockers were established. They are incomplete,
not clean checks. Server static diagnostics: 2 WARNING categories (missing docs,
codoc) and 1 NOTE (normalize/global references); client: 3 WARNING categories
(non-ASCII MI source, codoc, duplicate ordinal Rd argument). Detailed partial
reports are retained in `inst/cross-cox-v1/server-check_partial.txt` and
`client-check_partial.txt`. These implicated existing sources/docs are byte-for-
byte unchanged from the respective bases; new family code has no static warning.

The first client check also found our prematurely exported name missing from
its exact public inventory. Fixed by keeping the entry behind registration
(client c35322e), with all existing inventory tests and 39 Cox contract/parity
expectations passing together. The final client entry is internal; its public
export is explicitly part of the integration checklist. The full client check
was not repeated to completion after this repair.

The broad Go invocation completed 18 top-level tests and 25 subtests with no
observed failure before interruption in
TestFormalCoxBlockwiseLiveControlStagesFreshFinalizerK2K3K5/K2. Do not confuse this
partial legacy coverage with the completed 23-test Cox family gate. The partial
logs were copied before termination; `package_check_status.json` records their
SHA256s, commands, scope and interruption provenance. Only processes whose cwd
was inside /workspace/dsvert/cox/ were signalled; other lanes were untouched.

Final functional commits:
- Server dd25445 (recovery), 2f2c547 (circuits), 1bfe8a5 (R oracle/contract),
  88a0694 (measured evidence), 1938c4e (public-surface decision).
- Client 19b0e02 (recovery), 6b993e2 (DSLite/oracles), c35322e (internal entry).
Subsequent commits record this handoff and check evidence only. Both final diffs
against server 38146c0 / client cb26ecd contain only new family files. No existing
file is modified after removal of our own temporary NAMESPACE export.

## 2026-09-18 resumed — revised clauses 4 and 5

Both repositories were clean. The prior whole-envelope gate is superseded.
Restructuring uses one packed Ring128-share permutation per release, local
Ring64 prefix/loss sums, OT private tie selection, scalar-only profile batches,
and the topology-bound compact framing from fetched step-2 commit 0006f1a.
Private event counts require padded log batches. Authentication/fusion remains
the step-2 integration boundary; no plaintext or production fallback is added.

### Clause-5 implementation checkpoint

New family-only Go files implement compact topology-bound framing, packed
Ring128 Beneš routing through checked OT, Ring64 prefix/loss additions, private
OT tie-denominator selection, scalar exp/log batches, and keyed chunk receipts.
The single registration now exposes SharedPlan, SharedCompile and RunShares;
legacy Plan/Compile are retained for reference regression only.

Targeted local shared-profile, topology/plan and compact-digest tests pass.
The two-peer encrypted synthetic 34-row/2-candidate run also passes the integer
oracle on the pod: 33 chunks, 33,725,420 two-direction bytes, 122.876 s cold
compilation + 12.327 s online (135.203 s total). This is kernel evidence, NOT
an authenticated source-to-joint-DP release. Nine requested envelope shapes
are now running under /workspace/dsvert/cox/envelope-v2/; no capacity is admitted
until their completed measurements are reviewed.

R transcript v2 and canonical parity checks pass: server 626 expectations,
client 39. The default targeted client invocation skipped the explicitly tagged
DSLite fixture; its final run will supply the test-only executable.

### Completed validation and first measured envelope

Final hardened kernel passes the complete Cox Go family suite on the pod:
**21 top-level tests + 7 subtests**, with the opt-in envelope test skipped in
that ordinary suite. The first broad invocation used the wrong working directory
and four fixture-reading tests could not find their JSON; the corrected run from
`dsVert/inst/dsvert-mpc` passed. The launcher now records that required cwd.

The explicit tagged DSLite/pooled-Breslow validation passed **23 expectations**,
no failures/skips/warnings (10.415 s). Pod lacks devtools; the successful command
uses `testthat::test_local`, with DSVERT_COX_TEST_BINARY pointing at cox-oracle-v2.
Both full R CMD checks have reached their test phases; results remain pending.

First completed full family-kernel envelope: N=2000,J=16, M=2048, 2345 chunks,
8,472,921,669 measured two-direction bytes; cold compilation 115.183 s, online
1183.237 s, total **1298.420 s (21.64 min)**. Every candidate equals the independent
integer oracle. Source/PSI-to-joint-DP fusion is excluded explicitly, not claimed.
Final capacity selection waits for the remaining eight requested matrix points.

Client full R CMD check completed: **FAIL 0 / WARN 0 / SKIP 48 / PASS 25425**
in its test suite; overall check status **3 WARNINGs**, matching the previously
identified non-ASCII MI, codoc and duplicate ordinal argument categories.

The server check exposed an unchanged baseline structural test at
`tests/testthat/test-dp-count-execution.R:799`: it reads ../../R/dpCountExecutionDS.R,
which is not adjacent to tests in a built R CMD check directory. Both that test
and its target file are byte-identical to 38146c0. Preserve the interrupted
unseeded log, then rerun using `run_server_check_source_fixture_v2.sh`, which
links the EXACT extracted checked archive's R directory to the expected test
path. No package source or assertion is changed/skipped. This is a documented
check-environment fixture, not a repaired production feature or suppressed test.

Second completed envelope: N=2000,J=32, M=2048,
**16,943,647,939 bytes; 2355.695 s (39.26 min)** including 111.608 s compilation.
All 32 coordinates match the independent integer oracle. The 2000x50 and
4000x16 runs are active next; final admission is not selected yet.

Added a focused encrypted budget-abort regression: a two-candidate synthetic
run is cut by a 900,000-byte TEST transport limit, then both parties must return
no coordinate/validity arrays and the report must say incomplete/resource-stop.
`go test -run '^TestCoxGridCrossSharedBudgetStop$' -count=1 -timeout=30s .` passes.
This is additional targeted coverage after the 21-test broad family run; no
production epsilon/delta, loss cap or transport budget was changed.

### Resumed — 2026-09-18, additional completed matrix points

Both worktrees were clean on resumption. Preserved two more full encrypted
family-kernel reports with all candidate coordinates equal to the integer oracle:
2000x50: **26,473,265,394 bytes; 2940.744 s**, including 99.978 s compilation;
4000x16: **16,951,184,064 bytes; 1846.358 s**, including 61.373 s compilation.
The larger five points are still pending; no final admission is selected.
The isolated synopsis-artifact suite passes on BOTH current and primitive
baseline sources; full installed-server check failures remain under investigation.

Signed public resource admission is now implemented conservatively at the
largest COMPLETED point so far (2000 rows x 50 candidates). This is provisional
until all nine probes finish. Both R validators rebuild the admission metadata;
Go's registered SharedPlan/SharedCompile/RunShares reject excess dimensions
before compilation, I/O or source use. The internal measurement runner retains
the theoretical envelope to measure inadmissible points. Targeted Go admission
and both R Cox contract suites pass, including tampering re-signed by both peers.
