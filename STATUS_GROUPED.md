# Grouped lane status

## Resumed 2026-09-18

Recovered this lane after quota interruption on `feature/groupedimpl`.
Server base `38146c0`; client base `cb26ecd`. No prior grouped status,
decisions or blocked document existed. Primitive status is in STATUS_P.md.
All recovered implementation files were untracked except the additive client
NAMESPACE export. They are under audit, not a completed milestone.

Recovered: seven q16 linear profiles and coefficient JSON; single-cluster LMM,
GH5 GLMM and GEE emitters; server/client signed contracts; fail-closed release
entry points; partial integer oracles and tests. No production dispatch enabled.

Initial resumed checks:
- Pod install log contains R_STACK_DONE; /workspace/dsvert/grouped exists.
- `go test -run '^TestGrouped' -count=1 -timeout=10m .`: FAILED;
  unequal-width wideMul profile arguments and LMM compilation rejection.
- Focused R contract checks started; results pending.

Outstanding gates: compile/equality for all kernels, integer/certificate and
sensitivity audit, R parity, test-tag reference bridge, two-peer DSLite and
pooled-fit comparison, resource measurements, package checks, integration notes.
No completed production release or full-size performance claim.

### Recovered contract milestone

Focused server contract test file: 120 expectations, no failures.
Focused client contract test file: 151 expectations, no failures (before the
subsequent quarter-step score-clip parity restriction; rerun required).
LMM: all 3 tests pass, including real encrypted two-authority transport;
two-slot circuit 271075 gates / 2487376 table bytes; one-slot garbler direction
2843195 encrypted bytes. Fixed compiler constant-folding/cast hazards and
widened quantization from uint72 to uint88 for admitted cluster magnitudes.
GLMM compiled binomial/Poisson equality: both pass. GEE valid cases pass;
invalid-row reference returned a partial sum, now corrected to all-zero output.
Profile equality and exhaustive q16-lattice error checks pass, but measured AND
cost exceeds the mandatory target; this remains a failed promotion gate.

## Final resumed handoff — 2026-09-18

**BLOCKED for production/full-envelope delivery**, see BLOCKED_GROUPED.md.
This is not a completed implementation of the requested authenticated release.
Upstream Step 2 at c10bc0d also records a failed scalar cost promotion gate.
No pushes, thesis edits, primitive/shared Go changes, or same-owner changes.

Completed restricted milestones:
- Five signed R family contracts and mirrored client validators/entry points;
  one internal server registry and typed Go family registries, disabled reader.
- Bounded random-intercept LMM, binomial/Poisson GH5 and likelihood+bread+meat
  GEE (independence/exchangeable/AR1) cluster kernels and Go references.
- Piecewise q16 scalar profiles, manifest hashes, analytic interpolation bounds,
  exhaustive lattice error checks and 2695 compiled interval fixtures.
- Pure-R integer oracles; tag-only fixture reader; public-synthetic two-peer
  DSLite source comparison, client postprocessor, pooled lmer/glmer/geeglm
  comparison at epsilon 1,4,8. This simulates release noise and is NOT the
  unwired authenticated protected MPC/noise/PSI/ledger route.
- Numeric limitations and exact wiring recorded in NUMERIC_CERTIFICATE_GROUPED
  and INTEGRATION_GROUPED (with family-specific pointers).

### Final verification

| Check | Result |
|---|---|
| Ordinary full Go package compiled + all grouped tests | 9 top-level / 24 including subtests; 0 failures; 9.621 s |
| Server contract test file | 6 tests / 120 assertions; 0 errors, failures, warnings |
| Client contract test file | 5 tests / 151 assertions; 0 errors, failures, warnings |
| R vs tagged Go integer oracle | 1 test / 33 assertions; no warnings/failures |
| Synthetic two-peer DSLite comparison | 1 test / 202 assertions; no warnings/failures; 15 family/epsilon comparisons |
| Scalar cost gate | FAIL: 4027–5488 ANDs, target <=2000 |
| Full-envelope/certificate/authenticated release gates | NOT PASSED; see blocked/integration documents |

Synthetic comparison selected the exact real finite-grid best in 2/15 cells;
max observed profile-vs-real loss difference 0.04539266. These tiny synthetic
runs with conservative whole-vector Laplace scales make no utility success
claim. Machine-readable results and source hashes are in inst/grouped-validation.

Commands (workspace root except Go command):

```
(cd dsVert/inst/dsvert-mpc && go test -run '^TestGrouped' -count=1 -timeout=15m -json .)
(cd dsVert/inst/dsvert-mpc && go test -tags grouped_reference_test -c -o /tmp/grouped-reference.test .)
DSVERT_GROUPED_REFERENCE_BINARY=/tmp/grouped-reference.test Rscript -e '
  devtools::load_all("dsVert",quiet=TRUE)
  source("dsVert/tests/testthat/helper-cross-grid-integer.R")
  source("dsVert/tests/testthat/helper-grouped-integer.R")
  source("dsVert/tests/testthat/helper-grouped-contract.R")
  testthat::test_file("dsVert/tests/testthat/test-crossgrid-grouped-integer.R")
  testthat::test_file("dsVert/tests/testthat/test-crossgrid-grouped-dslite.R")'
```

Full legacy Go suite was not rerun; package compilation includes the unchanged
legacy sources/tests. No full Go regression-pass claim is made.

### R CMD check: not yet a completed clean check

Pod R_STACK_DONE was verified before use. Initial `R CMD check --no-manual`
failed on absent DBI/filelock/RSQLite and absent client suggests. Installed
DBI/filelock/RSQLite successfully. Optional absent packages include
DSMolgenisArmadillo, DSOpal, opalr and pkgdown; reruns use
`_R_CHECK_FORCE_SUGGESTS_=false`, retaining test execution. These are dependency
limitations of the pod; no baseline clean-check comparison is claimed.

At handoff, asynchronous checks remain active under
`/workspace/dsvert/grouped/final/`:
- Client `client-check.log`: installation, syntax and load checks pass;
  code analysis in progress. NOTE: unavailable dsVert namespace (client check
  started before server install completed).
- Server `server-install-ready.log`: isolated installation byte compilation in
  progress, then `server-check-ready.log` will record the check.
- Server runner PID 102403; isolated R library `/workspace/dsvert/grouped/Rlib`.
- Prior dependency failures remain in `server-check.log` and the `resumed/`
  check directory. Do not label them clean or merely pre-existing NOTEs.

Check source snapshot includes all R changes and the pre-optimization Go
emitters; R checks do not execute the tag-only Go fixture by default. Final Go
emitter validation is the separate Mac command/source hashes above. Do not
repeat completed targeted milestones when resuming; collect check logs first.

Implementation commits:
- Server c1fe030 (contract scaffolding), d4392f9 (kernels/oracles/tests/docs),
  6f96f10 (safe cost optimization, expanded fixtures and arithmetic blocker).
- Client 83512b6 (adapters), 872bb6d (profile hash/domain parity).

## Resumed 2026-09-18 — revised reviewer gate

Both repositories were clean at resume; no interrupted edits needed recovery.
Read the recorded handoff and binding gate revision before implementation.
The old <=2000 AND / <=30 GB finding is superseded, not a current blocker.
Current acceptance is <=5000 AND per scalar nonlinearity and <=60 GB measured
two-direction full-release traffic, with unchanged per-chunk runner caps.
Upstream Step 2 is also actively resuming; it has not delivered release wiring.
First new milestone: range-reduced exp and profile/circuit/oracle parity, then
re-evaluate the complete chunk cost, remaining certificates and release gates.
Prior pod checks still run; R_STACK_DONE reconfirmed.
