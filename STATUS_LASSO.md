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
