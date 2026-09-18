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

### Revised scalar milestone — 2026-09-18

PASS revised <=5000-AND scalar gate: softplus 2384, log 2240, sigmoid 2238,
sqrt variance 2934, inverse sqrt variance 3175, reduced exp table 2063,
complete range-reduced exp 4321. Counts include share addition/output mask.
Exact-rational generator verifies all 390 coefficients, not just dense samples.
All exp calls in GLMM/GEE now use range reduction and fixed barrel shifts.
Profile/hash changed in both validators; old signatures cannot admit new math.

Current targeted verification: 11 Go top-level / 25 with subtests passed,
0 failures, 1 opt-in resource probe skipped in the ordinary run (executed
separately on pod). Server contracts 120, client contracts 151, integer parity
45, synthetic DSLite 202 assertions; no failures, errors or warnings.
Synthetic lmer/glmer/geeglm comparison at epsilon 1/4/8 still selects the real
grid best in 2/15 cells; max profile/real loss difference is now 0.007068514.
These are synthetic comparisons, not authenticated protected releases.
Evidence: inst/grouped-validation/revised-validation.json and
revised-synthetic-comparison.json. Full pod Go regression run launched once
at this final code snapshot; collection pending.

Pod transport probe has separately found an excessive full-schedule mandatory
payload lower bound; this is not the old scalar gate failure. Complete results
and final disposition will be recorded after remaining probes and check logs.

## Revised gate handoff — 2026-09-18 13:40 UTC

**Blocked for production/full-envelope delivery by the composed workload's
traffic, not by the superseded scalar target.** See BLOCKED_GROUPED.md and
BENCH_GROUPED.md. The requested protected release is NOT complete.

The pod campaign passed all nine encrypted chunk probes (1 top-level / 9
subtests), 383.42 s total. Per-profile mandatory table payload lower bounds
for the hypothetical n=10000, grid=50 traversal are:
- LMM: 289.408 GB.
- Binomial/Poisson GH5: 442.677 / 603.141 GB.
- GEE, only p=3: 7243.389–7327.613 GB across both families and all correlations.

These are exact table-byte lower bounds from compiled chunks, NOT measured
full-release totals. Measured two-direction chunk traffic, generated-source
hashes and elapsed times are in revised-cost.json/log. All final local Go
source hashes match the pod. None of the nine chunks raises a runner cap.
The full workload would exceed 60 GB before source/routing/dot/noise traffic.
No protected input or release was run; no production gate was opened.

Completed this resume: certified range-reduced exp, all-table outward knot
certificates, safe full-word Boolean lookup sharing, Go/R/client profile/hash
parity, revised scalar cost assertions, exponent-boundary R oracle fixtures,
new synthetic reference-fit comparison and two-direction pod measurements.
Remaining work is explicitly enumerated in INTEGRATION_GROUPED.md, including
GEE error propagation and Go/R cap mapping, full-size domain/schedule support,
authenticated source/PSI/routing, chunk state, joint noise/sticky release and
client reader. Do not bypass these gaps using test fixtures or state strings.

### Broad checks: still pending, not a clean-check claim

At 13:39:56 UTC the once-launched final full Go suite had 43 terminal pass
events, no terminal failures yet, and was still in legacy Cox integration
checks. It remains running at:
`/workspace/dsvert/grouped/revised/full-go.jsonl`; exit file `full-go.exit`.
Command: `go test -json -count=1 -timeout=0 ./...`.
The benchmark expectation correction only changes the opt-in cost test, which
this ordinary full run skips. The final corrected cost test separately passes.

Both inherited R CMD checks reached testthat and remain active. They check the
prior snapshot, NOT the newly committed range-exp update. Logs:
`/workspace/dsvert/grouped/final/server-check-ready.log` and `client-check.log`.
Current findings include server static-analysis NOTE and documentation
warnings; client non-ASCII `R/ds.vertMI.R`, `.dsvert_exact_gc_run` codoc mismatch,
duplicate `analysis_id` in `ds.vertOrdinal.Rd`, and unavailable-dsVert-namespace
NOTE from check startup. The named client files match cb26ecd byte-for-byte;
server findings concern unchanged existing functions. This is not a completed
baseline comparison, and no pending test failure is classified as pre-existing.
No completed R CMD check or full-suite pass is claimed. Exact progress is in
inst/grouped-validation/revised-check-progress.json. Collect these running
checks first on any resume; do not restart them unnecessarily.

Commands additionally used this resume:
```
python3 dsVert/inst/certificates/grouped_exp_certificate.py --check
(cd dsVert/inst/dsvert-mpc && go test -run '^TestGrouped' -json -count=1 -timeout=15m .)
(cd dsVert/inst/dsvert-mpc && go test -tags grouped_reference_test -c -o /tmp/grouped-revised-reference.test .)
# R: devtools::load_all paired source; source the grouped helpers; test_file:
# server test-crossgrid-grouped.R, test-crossgrid-grouped-integer.R,
# test-crossgrid-grouped-dslite.R; client test-dp-grouped-grid-cross.R.
# Set DSVERT_GROUPED_REFERENCE_BINARY to the tagged executable for oracle/DSLite.
# Pod, from revised/dsVert/inst/dsvert-mpc:
DSVERT_GROUPED_COST_PROBE=1 go test -run '^TestGroupedRevisedGateMeasuredCosts$' -v -count=1 -timeout=30m .
```

Resume commits: server 43370ce (resume), 4f2d314 (certified arithmetic),
067ac0a (resource evidence/handoff); client 016e400 (profile binding),
607b0aa (status). The final status-only commit is identified by
`git log -1 -- STATUS_GROUPED.md`. No pushes, thesis edits, shared producer
changes, same-owner changes or generation-one changes.

## Resumed 2026-09-18 — clause 5 audit

Clean worktrees at resume. Fetched Step 2 through 8b6c7bf. The old
per-cluster traffic finding is superseded and cannot set the new capacity.
Import the explicitly requested compact framing from 0006f1a; move exact
linear operations to local shares. Audit secret products, live-count
reciprocals and private boundaries separately; none is a local linear map.
Inherited full Go and R checks still have no terminal result on the pod.

### Clause-5 implementation and verification — 2026-09-18

The historical release-traffic blocker is withdrawn. No new full-release
traffic rejection is asserted. Protected release remains incomplete; see the
replaced BLOCKED_GROUPED.md and CLAUSE5_ARITHMETIC_GROUPED.md for the exact
arithmetic/fusion dependency and unresolved lane work. No capacity in the
requested 3x3 matrix is admitted from component-only measurements.

Completed in this resume:
- Scalar-only q16 chunks (1..32 values), private domain guards and aggregate
  validity; invalid batches zero all outputs. Existing certified arithmetic
  and profile hashes remain unchanged.
- Local exact fixed-public-block share sums; no local squaring, truncation,
  secret-boundary branch or ring-width change is substituted for secure MPC.
- Requested compact engine import, grouped internal wrappers and independent
  record-key domain for compact framing. Legacy routes remain untouched.
- New registry entries quarantine the three client prototypes. Fixed this
  lane's package-check inventory regression without advertising promotion.

Verification:
- Mac grouped plus affected legacy protocol/record tests: 23 top-level passes,
  56 including subtests, zero failures; one old opt-in cost probe skipped.
  After record-context separation: 12 affected top-level / 31 with subtests
  passed, no failures (includes all seven scalar chunks and legacy transport).
- Exact-rational 390-knot and ln2 certificate checker: PASS.
- Client focused tests: grouped registry 8, capsule inventory 912, maturity
  166, grouped contracts 151 assertions = 1237; zero failures/errors/warnings.
- Pod count=32 scalar components pass all seven profiles including guards and
  masks; see BENCH_GROUPED_CLAUSE5.md and clause5-components.json. Both traffic
  directions are measured. Code hashes checked against the Mac.
- First count=32 probe rejected exp because conditional array writes inflated
  mux cost. Fixed with scalar temporaries; no gate limit was changed.

Commands:
```
# dsVert/inst/dsvert-mpc
 go test -run '^(TestGrouped|TestExactGCProtocolEndToEnd$|TestExactGCProtocolFreshArithmeticShares$|TestExactGCSecureRecords)' -json -count=1 -timeout=15m .
 DSVERT_GROUPED_SCALAR_PROBE=1 go test -run '^TestGrouped(Scalar|ShareBlock|ClauseFive)' -json -count=1 -timeout=5m .
# workspace
 python3 dsVert/inst/certificates/grouped_exp_certificate.py --check
# Client: devtools::load_all; test_file the four files named above.
```

Inherited client R CMD check completed: 1 ERROR, 3 WARNINGs, 1 NOTE; tests
23868 pass / 1 failure / 51 skipped. Its error was the missing grouped inventory
entries, now corrected by 429b2a7 and targeted tests. No clean-check claim.
Warnings concern unchanged ds.vertMI.R non-ASCII, existing codoc mismatches,
and duplicate analysis_id in ds.vertOrdinal.Rd. The first and last files were
reconfirmed identical to cb26ecd. The inherited check's dependency NOTE is
not a final check of this revision. Full Go and server R checks remain running
at their previously recorded paths; no final pass is inferred from progress.

Client R CMD build succeeds on the new snapshot. The required post-fix check
is running under /workspace/dsvert/grouped/clause5/: client-check.log and
client-check.exit. It uses the isolated Rlib, explicit companion source path,
_R_CHECK_FORCE_SUGGESTS_=false, and retains tests. Collect rather than restart.
The full protected two-peer DSLite release and its 3x3 performance matrix are
NOT implemented; prior synthetic reference-fit comparisons remain the only
DSLite utility evidence and must not be relabelled as authenticated releases.

Commits: server f71d98c (resume), a5c7dc2 (components/compact engine),
33c54d6 (record-domain separation); client 429b2a7 (registry regression fix).
The final evidence/status commit is identified by git log -1 -- STATUS_GROUPED.md.
No pushes, thesis edits, same-owner behavior changes or production promotion.

Final record-domain-separated pod probe: 4 top-level / 11 including
subtests pass, zero failures/skips, 146.310 s. Log scalar-context-final.jsonl.
All recorded Go source hashes match between Mac and pod. The final JSON
separates pre-context broad Mac regression from post-context affected tests.

## Resumed 2026-09-18 — Addendum 3 arithmetic ownership

Both repositories are clean. The reviewer assigns dealer-free checked-OT exact
arithmetic to this lane; the prior ownership dependency is resolved. Implement
wide-ring Beaver products first, then candidate-independent LMM statistics,
GEE and GH5 composition. Do not reuse Ring127 truncation or widen shares by
zero extension. Full-release capacities still require full measurements.
Inherited pod checks still have no exit files; R_STACK_DONE reconfirmed.

### Addendum 3 arithmetic milestone — 2026-09-18

Server 80aee12 adds dealer-free checked-OT Ring192 Beaver products, one internal
registration, context/role-bound encrypted records and local share receipts.
No production dispatcher added. Final pod batch: 1024 products, 37,912,128
bytes in BOTH directions, 7.903936 s. Mac race check passes; integer oracle,
freshness, malformed plan and contract/chunk/count/tamper/role/replay tests pass.
See inst/grouped-validation/dealer-free-product.json. This is a component
measurement, not an admitted release envelope or a full-release cost estimate.

Next implemented components: candidate-independent LMM moment schedule,
private reciprocal selection, exact f164 precision Gram assembly, carry-correct
signed lifting into two Ring192 limbs, local public-beta f264 accumulation,
and one final clamp/ties-even output rescale. Go boundary/grid/oracle tests
pass, including two-authority encrypted moments; pure-R integer oracle agrees
with the tagged Go executable (5 assertions). R contract tests: server 120,
client 151 assertions pass. Both R sides bind the new LMM profile; old integer
profile is retained only as an explicit LegacyCompile test prototype.

The grouped Go run before the final certificate-only test added here passed
26 top-level / 53 including subtests, no failures, one opt-in probe skipped.
Final combined verification will include the certificate test and final R
profile metadata. No full-suite or R CMD check completion is claimed.
Inherited pod checks still have no terminal exit files at collection.

This is work in progress: GEE/GH5 share composition and error/cap parity,
source/primitive/fused release integration, measured full-release 3x3 envelopes,
protected DSLite lifecycle and final package checks remain. Do not attribute
all remaining lane implementation to the external Step-2 fusion dependency.

### Addendum 3 current verification and unfinished work

Latest targeted verification (final code snapshot):
- Mac grouped Go: 35 top-level / 69 including subtests PASS, no failures,
  one old opt-in resource probe skipped; 19.034 s. Compiles ordinary package.
- Pod new components: 6 top-level PASS, no failures/skips; 9.616 s. The
  count-32 Ring192 exp bridge uses 5,252,563 two-direction bytes / 0.901655 s.
  Carry-correct lift: 89,936 bytes / 0.110025 s. LMM final boundary:
  277,399 bytes / 0.261466 s. No full-release inference is made from these.
- R: server contracts 120, existing oracles 45, new LMM oracle 5, synthetic
  DSLite comparisons 202, client contracts 151 = 523 assertions; all pass,
  no warnings/errors. DSLite now uses the NEW tagged LMM statistic. These
  remain public-synthetic comparisons with simulated noise, not authorization.
- Evidence: addendum3-validation.json and addendum3-synthetic-comparison.json
  under inst/grouped-validation, including source hashes and measurement scope.

Commits: 80aee12 exact OT products; 6587bc1 LMM statistics/boundaries;
975e676 wide scalar bridge and GEE moment boundaries; 74571c0 GH5 composition;
6670595 new LMM synthetic comparison. Client 91ea81b binds the new LMM profile.
No pushes, thesis edits, same-owner changes, shared Step-2 edits or promotion.

GEE moment tests use supplied whitened factors; they do NOT validate the missing
private correlation/whitening producer. GEE propagated certificate and new
integer/R profile parity remain incomplete. GH5 preserves its existing integer
oracle but still needs authenticated source/mask/factorial and chunk scheduling.
All families still need integrated full-release measurement/admitted capacities.

Fetched upstream through 2f36f79: internal fused GLM/noise components exist,
but authenticated R admission/source/lifecycle/client fusion remains explicitly
unfinished. BLOCKED_GROUPED.md replaces the old dependency claim with measured
component results, the precise external gap, and separate owned open work.
This lane has NOT completed the requested protected release or full envelopes.

Inherited checks remain running, not passed: revised/full-go.jsonl was in the
legacy Cox live-control K3 test at last collection; final/server-check-ready.log
and clause5/client-check.log remain in testthat. No completed R CMD check of
this new snapshot is claimed. Do not classify pending failures as pre-existing.

Commands from dsVert/inst/dsvert-mpc:
```
go test -run '^TestGrouped' -json -count=1 -timeout=15m .
go test -race -run '^TestGrouped(WideRingOracle|DealerFreeProduct|ArithmeticRejects|ArithmeticRecord)' -count=1 -timeout=5m .
go test -tags grouped_reference_test -c -o /tmp/grouped-stats-reference.test .
DSVERT_GROUPED_ARITHMETIC_PROBE=1 go test -run '^TestGrouped(WideRingOracle|DealerFreeProduct|ArithmeticRejects|ArithmeticRecord|LMMMoment)' -json -count=1 -timeout=10m .
DSVERT_GROUPED_WIDE_PROBE=1 go test -run '^TestGrouped(WideScalarEncrypted|LMMWideBoundaryEncrypted|LMMStatsCertificateBound|GEEExactMomentComposition|GLMMShare)' -json -count=1 -timeout=10m .
```
R tests use the tagged binary via DSVERT_GROUPED_REFERENCE_BINARY and the
helpers/test files named in the prior entries; the new file is
`test-crossgrid-lmm-stats-integer.R`. No ordinary executable contains its fixture.
