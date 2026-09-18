# LASSO cross-owner status

## Day 1 arithmetic continuation — 2026-09-18

The public finite-grid L1 extension is retained. Binomial/Poisson production
integration now requires the certified piecewise-polynomial base producer from
`DECISION_DAY1_ARITHMETIC_ROUTE.md`; the historical q64 numeric certificate is
not claimed for that producer. Gaussian keeps the existing sufficient-statistic
route. This lane adds no nonlinear kernel and reads no protected data.

Milestones retained/completed:

- Exact public binary64 penalty ceiling (including subnormal positive values),
  signed finite candidates, unique base-coordinate reuse and zero additional
  sensitivity are implemented in both packages.
- Both-custodian Ed25519 validation binds the base digest, candidate order,
  penalties, lattice, capacity and inherited sensitivity. Policy lattice/pins
  and Gaussian moment order/dimensions/maxima are checked consistently.
- One `.dsvert_dp_lasso_cross_register()` function per package exposes the
  family integration seam and the required arithmetic dependency. Required ABI
  state strings stay unchanged; production release remains disabled.
- Numeric documentation expresses total normalized objective error as inherited
  base loss error plus strictly less than `1/(N*2^g)` public penalty error.
- Tests cover penalty slack/subnormals, candidate/cap/hash/signature tampering,
  public coordinate reuse, unchanged sensitivity, Gaussian cross terms, public
  capacity normalization and canonical ties.

Validation commands and results:

- Client focused command: `Rscript -e 'pkgload::load_all("dsVertClient", quiet=TRUE);
  res <- testthat::test_file("dsVertClient/tests/testthat/test-dp-lasso-grid-cross.R",
  reporter="summary")'`: 11 test blocks / 104 expectations, 0 failures,
  0 errors, 0 skips. This run loaded before the final family-override rejection
  assertion; that last guard is checked separately from current source.
- Initial server focused run: 7 test blocks / 80 expectations, 0 failures,
  0 errors, 0 skips. This run parsed before the three new regression blocks were
  appended; it is not a final-code test count. Final focused reruns of both
  packages are in progress.
- Current-source isolated guard check: both server and client passed seven
  typed fixed-message rejection cases (including the last family-override
  guard), plus the required profile registry assertion. The first isolated
  client invocation omitted its schema/failure-helper source file and was
  corrected before this completed pass; it was a test-runner dependency error.
- Both R implementation files and both final focused test files parse cleanly.
- Independent public-arithmetic audit: 120 deterministic Python `Fraction`
  exact-rational penalty cases (seed 20260918; normal/subnormal coefficients,
  lambda, capacities 1/7/17/65537, g in 8/16/18) compared with the sourced pure-R
  penalty evaluator: all 120 exact equalities passed. This check uses only
  synthetic public candidates, not package authentication or MPC.
- `git diff --check` in both packages: passed for tracked changes.
- `./pod4 'tail -5 /workspace/logs/install_r.log'`: helper exited before connecting
  with `Bad port ''`; local focused tests remain available. No pod test result
  is claimed from this command.
- Parent family session owns the tagged Go reference/DSLite harness, centralized
  reference comparison, paired package checks and final commits; its results
  must be recorded explicitly before any promotion claim.

Open integration gates are enumerated in `INTEGRATION_LASSO.md`: authoritative
Step 2 profile validation, fused producer registration, authenticated result and
joint-noise evidence, sticky release binding, client orchestration, and the
existing Gaussian manifest/certificate adapter. Signed state markers do not
prove execution. Same-owner and sealed generation-one routes remain untouched.


## Final-source audit

The last implementation change rejects fractional raw coordinates at the common
integer lattice boundary while retaining negative integer DP noise values.
Isolated current-source checks passed in both packages: two accepted integer
cases and four typed fractional rejection cases each. Independently constructed
server/client public Gaussian descriptors and LASSO specs, including hashes,
were identical. Both implementations' penalty/base/postprocessing function
bodies also matched after the required package-specific hash/failure names.
Production and test files are now frozen; fresh final focused suite counts will
be recorded below. Earlier in-flight runs started before the last assertion and
are not used as final-source counts.

Final client focused run after all implementation/test edits: **11 test blocks,
106 expectations, 0 failures, 0 errors, 0 skips**. Command from `dsVertClient/`:

```sh
Rscript -e 'pkgload::load_all(".", quiet=TRUE); res <- testthat::test_file("tests/testthat/test-dp-lasso-grid-cross.R", reporter="summary"); saveRDS(res, "/tmp/dsvert-fama-lasso-client-settled.rds")'
```

The server focused suite is being transferred to the now-ready pod R stack by
the shared harness/check session. Its completed result will supersede the local
in-flight run; no source changes are planned while it runs.

## Authoritative final focused results

The final frozen-source **server** run completed locally before a separate pod
run was needed: **10 test blocks, 104 expectations, 0 failures, 0 errors,
0 skips**. The final frozen-source **client** run above completed with **11 test
blocks, 106 expectations, 0 failures, 0 errors, 0 skips**. These 210 expectations
supersede earlier in-flight runs. One earlier server run loaded the pre-guard
implementation and then parsed the newly added fractional-coordinate assertion;
that stale-source run had one failure and was discarded, followed by these
completed frozen-source runs.

Reproduce from each package directory (use the respective test path):

```sh
Rscript -e 'pkgload::load_all(".", quiet=TRUE); res <- testthat::test_file("tests/testthat/test-crossgrid-lasso.R", reporter="summary"); out <- as.data.frame(res); stopifnot(!any(out$failed > 0 | out$error))'
Rscript -e 'pkgload::load_all(".", quiet=TRUE); res <- testthat::test_file("tests/testthat/test-dp-lasso-grid-cross.R", reporter="summary"); out <- as.data.frame(res); stopifnot(!any(out$failed > 0 | out$error))'
```

Local completed RDS records are `/tmp/dsvert-fama-lasso-server-settled.rds` and
`/tmp/dsvert-fama-lasso-client-settled.rds`. The shared harness/check session owns
paired package `R CMD check`, DSLite and tagged Go reference evidence. No focused
public-algebra result here claims production MPC, noise, replay or release
integration; those gates remain described in `INTEGRATION_LASSO.md`.


## Implementation commits

- Server `9ff7d277b22aeb2181f9901c2b29abfd29391ec3` — isolated LASSO contract, public penalty, adapter, tests and documentation.
- Client `786c6e8321277c75bbfebdbe418ac6ce99cc54fb` — mirrored signed contract, fail-closed public API, tests and manual.

These commits leave the shared NAMESPACE registration and combined reference
harness to the parent integration session. This status record is followed by a
documentation-only commit recording the implementation identities. No remote
push or same-owner/sealed-route edit was performed.

## Combined final pod campaign

The paired final pod suites repeated all **104 server + 106 client LASSO
expectations** successfully. The tagged two-peer DSLite reference harness also
passed **2 blocks / 97 expectations**, covering NB plus binomial, Poisson and
Gaussian LASSO at epsilon 1, 4 and 8. All 12 fixed synthetic cases selected the
exact signed-grid best; pooled reference coefficients/objectives are recorded
in client `inst/cross-grid-nb/reference_validation_fama.json`.

This is bounded reference evidence: binomial/Poisson use the frozen Step 1
oracle pending the parallel piecewise adapter. Gaussian moment arithmetic and
client artifact validation pass; its synthetic peer staging uses common NB
metadata and does not complete authenticated Gaussian server-manifest/session
coverage. The report marks both limitations. Seeded noise replay is test
reproducibility, not a production sticky-ledger test. See `STATUS_NB.md` for
commands, counts, per-workload approximation/noise ratios and complete context.

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
