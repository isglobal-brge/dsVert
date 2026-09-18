# NB family status

## Resumed baseline and milestones

This is the continuation of Family A on `feature/famA`, from server `4d7e6ae`
and client `cb26ecd`. Existing NB/LASSO changes were present as uncommitted new
files; no previous NB status or decisions file was present. The binding Day 1
arithmetic decision was read first. The source Step 1 status was located and
read at `/Users/david/Documents/GitHub/dsvert-crossowner/dsVert/STATUS_V1.md`;
it is absent from this worktree's pinned commits. That status reports pending
full suites and five pre-existing Go failures, not a clean full-suite baseline.

- Preserved paired public theta/beta candidates, all-custodian signatures,
  frozen source layout, PSI/validity binding, states and fail-closed client seam.
- Retargeted NB nonlinearity to certified q16/w32/K64 quadratic softplus;
  retained correct complete NB2 loss and exact Go/pure-R profile semantics.
- Replaced NB public caps with profile-aware endpoint enclosure and certified
  integer constants; retained whole-vector adjacency and representability gates.
- Added profile boundary/tie/slack, dense error, cap/sensitivity, signature and
  production fail-closed checks, plus the tagged DSLite reference campaign.
- Preserved same-owner and generation-one production files. Shared edits are
  limited to additive client exports. No push, deployment or thesis edit.

## Commands and verification

The pod helper cannot connect: `pod4_endpoint` contains only a newline and
`./pod4 'tail -5 /workspace/logs/install_r.log'` returns `Bad port ''`.
`R_STACK_DONE` could not be checked. Verification uses the local R 4.5.2 / Go
installation. The shared host is heavily oversubscribed (load about 80 on
8 logical CPUs); interrupted exploratory runs are excluded from final counts.

Reproduction commands (from the indicated package root):

```sh
# dsVert/inst/dsvert-mpc
 go test -count=1 -run '^TestCrossGridNBV1' -v
# dsVert
 python3 inst/cross-grid-nb/generate_numeric_profile_nb_v1.py inst/cross-grid-nb/numeric_profile_nb_v1.json --check
# workspace root, focused R checks after loading the corresponding package
 Rscript -e 'pkgload::load_all("dsVert",quiet=TRUE); testthat::test_file("dsVert/tests/testthat/test-crossgrid-nb.R")'
 Rscript -e 'pkgload::load_all("dsVertClient",quiet=TRUE); testthat::test_file("dsVertClient/tests/testthat/test-dp-nb-grid-cross.R")'
# DSLite and package check commands/results are appended below after completion.
```

Final counts and commit IDs: pending verification completion.

## Promotion gates

| Gate | State |
| --- | --- |
| Frozen source ABI and two-authority signed contract | Implemented; tests pending final tally |
| Correct NB2 profile and matching R/Go integer references | Implemented; tests pending final tally |
| Analytic error and approximation-aware U, Delta1, Delta2 | Implemented; tests pending final tally |
| Default-envelope error below 1% of Laplace noise scale | Regression test included |
| Measured <=2000 AND gates per nonlinear evaluation | Measurement pending |
| Test-tag-only DSLite arithmetic/reference path | Campaign pending |
| Production source/result evidence, joint DP and sticky release | Closed; wiring belongs to parallel integration session |
| Package checks | Running separately; full repository suite not claimed |

See `INTEGRATION_NB.md` for exact remaining wiring. State strings do not
establish producer execution or authorize release. The reference harness is
synthetic arithmetic/contract evidence, not a production MPC/privacy campaign.

## Final arithmetic and focused validation (supersedes pending entries above)

The pod endpoint became available during this continuation. After the
`R_STACK_DONE` marker was present, final source snapshots and R checks moved to
`/workspace/dsvert/nb/`. The earlier blank-endpoint failure and oversubscribed
local exploratory runs are not final verification evidence.

- Go: six top-level NB tests and three compiled-theta subtests passed. The
  profile test evaluates 440,001 dense points plus 650 breakpoint/tie checks;
  maximum sampled softplus error is 0.0000300918, below the analytic 0.00003936
  certificate. There are 881 compiled profile/reference comparisons.
- A separate final compiled-row test passed 36 comparisons across theta
  exponents -3, 1 and 7, including unsaturated y=2/y=17 negative constants,
  validity masking, saturation, encoded boundary slack, one-integer-outside
  range and signed-minimum rejection. Reproduce with
  `go test -count=1 -run '^TestCrossGridNBV1CircuitMatchesIntegerReference$'`.
- The interval generator's `--check` reproduces its JSON byte-for-byte; server
  and client profile files are identical. Go profile/row code has no command
  registration or plaintext production evaluator.
- Final pod NB server: **12 test blocks / 3,671 expectations**, zero failures,
  errors or skips. Final pod NB client: **14 blocks / 3,683 expectations**,
  zero failures, errors or skips. These replace the interrupted local runs.
- Final pod LASSO: server **10 blocks / 104 expectations**, client **11 blocks /
  106 expectations**, all passed. The source-harness static checks pass seven
  assertions; the opt-in campaign is executed separately.
- Independent cap audit verified the exact upward decimal conversion and
  endpoint/enlargement proof. Public endpoint floating arithmetic is below
  2^16 and its conservative rounding allowance is less than 9.32e-10, well
  below the signed 2^-20 guard.
- Only pre-existing source files modified are the two additive client NAMESPACE
  exports. Same-owner, generation-one and shared engine code are unchanged.

The two exploratory NB test failures were fixture assertions, corrected before
these final pod runs: insertion-ordered layout lists were incorrectly compared
with canonically sorted named lists; the constant tamper test wrote zero over
an already-zero y=1 constant. Canonical ABI equality and actual changed-byte
rejection both pass. No production validator was weakened to resolve them.

The final nonlinearity cost is **5,720 AND gates / 17,989 total gates /
183,056 garbled bytes per evaluation**, or **91.528 GB** for 500,000 evaluations
before OT/framing. This fails the binding cost target; `BLOCKED_NB.md` records
the remaining primitive dependency. Full-row reference adapters have 1,300,472
gates and are not a production cost model. Source/evidence/joint-DP/sticky
release gates remain closed as documented in `INTEGRATION_NB.md`.

Implementation commits so far:

- Server `633852b`: q16 certified profile, Go kernel/reference and certificate.
- Client `24b98b1`: identical pinned NB profile artifact.
- Server `810090e`: unsaturated compiled NB constant-table coverage.
- Server `c46cc3e`: signed profile-aware caps, pure-R oracle, validators and docs.
- Client `2c8e37c`: NB client/oracle/tests/manual and two additive family exports.
- LASSO server `9ff7d27`, client `786c6e8`; status record `28c5df9`.

Package-check and complete DSLite campaign results are appended next when the
remaining verification finishes; no production promotion is claimed.

## DSLite reference campaign

Final pod command from `dsVertClient/`, with the family-private R library on the
library path:

```sh
DSVERT_RUN_FAMA_REFERENCE=1 Rscript -e 'pkgload::load_all(".",quiet=TRUE); r <- testthat::test_file("tests/testthat/test-fama-reference-harness.R",reporter="summary"); stopifnot(!any(as.data.frame(r)$failed), !any(as.data.frame(r)$error))'
# Standalone reproduction of the saved synthetic result:
Rscript tools/validate_fama_reference_dslite.R --output=inst/cross-grid-nb/reference_validation_fama.json
```

**2 test blocks / 97 expectations passed**, with no failures, errors or skips.
All **12 cases** (NB, binomial LASSO, Poisson LASSO, Gaussian LASSO at epsilon
1, 4 and 8) selected the exact signed-grid best for the fixed public synthetic
seed. The report also compares selected coefficients/objectives with pooled
`MASS::glm.nb` / `glmnet` fits. NB separately reports the fitted-theta objective
and the common signed-theta objective; these are different comparisons.

The tagged Go CLI passed **11 input subcases**, including f50 endpoint and
beta=8 acceptance, invalid coefficient/L1/canonical encodings, rounded numeric
and exponent feature rejection, unknown fields, theta range and trailing data.
It is absent from normal Go source files even with its build tag and from
untagged test files. Production client calls and missing-signature controls
fail closed. The exact-decimal CLI transport preserves f50 integers that JSON
floating formatting had rounded in an exploratory harness run.

Saved evidence: client
`inst/cross-grid-nb/reference_validation_fama.json`, with R 4.6.1, Go 1.25.7,
96-CPU pod context, numeric hashes and explicit pending routes. All data and
fits are synthetic. The harness's seeded noise replay is reproducibility
only, not evidence of a production sticky ledger or authenticated joint sampler.

The NB three-candidate campaign's certified aggregate-error/noise-scale ratios
are approximately 0.02524, 0.10098 and 0.20195 at epsilon 1, 4 and 8. These are
not the separate 50-candidate default-envelope 1% acceptance fixture. No general
small-error/noise claim is made for this small comparison grid. Both privacy
sensitivity and numeric error are explicit; production plan utility acceptance
remains required by `INTEGRATION_NB.md`.

Binomial/Poisson arithmetic in this campaign is the frozen Step 1 reference,
explicitly marked as pending the parallel Step 2 piecewise adapter. Gaussian
uses the existing moment arithmetic/client artifact validation; two-peer
synthetic staging currently authenticates the common NB metadata fixture,
not a full Gaussian server manifest/session. Those three cases do not establish
signed Gaussian server-path completion. No campaign result establishes a
production fused MPC, PSI, joint-noise or sticky release path.


## Final reference commits and verification scope

- Server `92f29ee`: test-build-tag-only exact-integer reference CLI and its
  11 rejection/acceptance subcases.
- Client `a0c33bc`: source-only two-peer synthetic DSLite campaign, opt-in test
  and saved reference comparison report.

The authoritative focused results are the separate NB/LASSO suite results and
`/tmp/fama-pod-validation/harness-e2e.log` / `harness-e2e.rds` for the final
97-expectation campaign. The earlier combined client-focused JSON contains a
superseded source-location assertion failure and an intentionally skipped
opt-in campaign; it is not the final harness result. The final source-location
assertion and complete campaign both pass in the separate record. Total final
focused R assertions across the two packages and harness: **7,661**, with no
failures, errors or skips.

The final documentation commit contains this status, decisions, integration
limitations and the measured NB blocker. Its identity is the family branch
server HEAD after the listed implementation commits. Both repositories retain
separate commit histories; no remote push was performed.

## Resumed — 2026-09-18 (reviewer quota-outage continuation)

Read the binding arithmetic decision and existing family records before edits.
Server HEAD was `92f29ee`; client HEAD was `a0c33bc`. Client was clean; server
contained coherent documentation updates only, retained in this continuation.
No implementation milestone was restarted. Existing focused test evidence is
preserved. Package-check completion is the remaining verification task; full
checks with tests enabled are being recorded separately from earlier no-tests
checks. Production gates and the measured NB cost blocker remain unchanged.

### Resumed public-surface correction — 2026-09-18

Full client package testing identified an introduced inventory regression: the
two new exports were absent from the shared public maturity inventory, whose
contract requires all analysis entries to be promoted. Removed only our two
NAMESPACE additions; keep the implemented entry functions namespace-internal
and available through family registration until integration can register real
production evidence and public status together. This supersedes earlier claims
that the staging functions are exported. No maturity test or shared registry
was weakened; adding exports is now an explicit integration gate.

Client correction commit: `112a820`. Corrected-source method inventory check
passed **13 blocks / 891 expectations** with `pkgload::load_all(export_all=FALSE)`
and `testthat::test_file(..., env=new.env(parent=asNamespace("dsVertClient")))`.
An initial runner omitted that namespace parent and could not resolve internal
functions; it is superseded by the successful run. Evidence:
`/workspace/dsvert/nb/validation/client-inventory-final.{log,rds,exit}`.

### Full-check checkpoint — 2026-09-18

Both full package checks were launched on the ready pod in
`/workspace/dsvert/nb/check/` using
`R CMD check --no-manual --no-build-vignettes dsVert_1.2.0.tar.gz`
and the analogous `dsVertClient_1.2.1.tar.gz`. Tests are enabled.
Libraries: `/workspace/dsvert/nb/rlib`, plus the checked server library for
the client. Missing suggested packages were installed, without disabling
dependency enforcement. The pod reports 96 CPUs but its cgroup CPU quota is
765000/100000 = 7.65 CPU-equivalents shared with concurrent sessions.

Logs and eventual exit codes are
`/workspace/dsvert/nb/validation/check-{server,client}-full.{log,exit}`;
full test output is under each package's `.Rcheck/tests/testthat.Rout*`.
At this checkpoint both tests remain active; server check PID 83548 / test
PID 95251, client check PID 88951 / test PID 95384. Do not start duplicate
runs if this session is interrupted. The client tarball predates the verified
export correction `112a820`; its inventory failure is superseded only by the
891-expectation corrected-source inventory run, not by a claimed clean full
check. Server has emitted a source-layout failure reproduction for unchanged
`test-dp-count-execution.R:802`, which reads an absent source R file from an
installed-package check tree. Final summaries are still required.

### Completed client package verification — 2026-09-18

The full client check finished: **29,193 passing expectations, 1 failure,
47 skips**, with zero test warnings. The only failure is the premature-export
inventory assertion fixed by `112a820` and rechecked successfully (891
expectations). Skips include repository/sibling-source-dependent audits and
opt-in campaigns; the separate family source campaign already passed. This is
not described as a clean full check on the final source.

Rebuilt final-source client check:
`R CMD check --no-tests --no-manual --no-build-vignettes dsVertClient_1.2.1.tar.gz`
in `/workspace/dsvert/nb/check-final/` completed with **exit 0, 3 WARNINGs**,
no errors or notes. A programmatic comparison confirmed all three complete
warning blocks are byte-identical to `baseline-client-check.log`: existing
missing documentation, code/documentation mismatches and duplicated ordinal
`analysis_id` documentation. No test or dependency gate was disabled in the
preceding full-suite run. The final packaging check explicitly skips tests
because the full suite and targeted correction were checked separately.

Local evidence: `/tmp/fama-pod-validation/check-client-{full,final}.log`,
`check-client-final.exit`, `client-inventory-final.log`, and
`testthat.Rout.fail` (the earlier full client run).
