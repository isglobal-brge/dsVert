# Multinomial cross-owner grid status

## Retained work and Day-1 arithmetic amendment (2026-09-18)

This work continues branch `feature/famB`, server base `4d7e6ae` and client
base `cb26ecd`. The existing family contracts, circuit sources, integer
references, tests and client frontdoors were present as uncommitted files.
They are being retained and reparametrized. No prior `STATUS_MULTINOMIAL.md`,
`DECISIONS_MULTINOMIAL.md` or `STATUS_V1.md` exists in this checkout; this is
the first available status record, not a reconstruction of unobserved tests.

The binding `../DECISION_DAY1_ARITHMETIC_ROUTE.md` supersedes the former
q64 nonlinear profile. The source feature/coefficient f50 ABI, exact f100
partial predictors, authenticated contracts, canonical candidates, private
alignment requirements and output g=8..18 remain in force.

Milestones:

1. Read the arithmetic decision, V1 decisions/certificate, design and existing
   family code; split profile/circuit, certificate/oracle, and client validation
   work without shared-file edits.
2. Retarget nonlinear evaluation to certified public piecewise polynomials;
   bind the table and certificate identities into both signed validators.
3. Validate circuit/reference/R equality, bounded sensitivity, numeric error,
   two-peer public-synthetic DSLite reference selection and both R packages.
4. Record measured cost, remaining fused-producer gates and small local commits.

The supplied `pod4_endpoint` is empty; `./pod4` reports `Bad port ''`.
Local R 4.5.2, Go 1.25.7, DSLite, nnet and MASS are available. No pod address
or readiness claim is inferred. Production release registration remains
disabled. No push or thesis edit is authorized or performed.

Test counts, commands, measurements and final commits are appended below
after execution. An incomplete milestone above is not a passing gate.


## Completed numerical and reference validation

Active profile: `cross-grid-multinomial-piecewise-q16-v1`.
Profile SHA256: `fc0d85381d6effb30776848ccf301f4b9b18fc5dc55bdc80a8503f7d8916fcef`.
Certificate SHA256: `b480edd4ab1ad8f2403026f2d718bfd093068816160a893ee0f7935056251f67`.

The following counts are **shared family-B lane totals**, not separate totals
for each family. All completed tests below have zero failures/errors/warnings
or skips unless a test is explicitly described as build-gating evidence.

| Verification | Completed result |
| --- | --- |
| Go loss/profile suite | 13 top-level tests + 9 subtests passed; 9.945 seconds test runtime |
| Main server contract/sensitivity/oracle tests | 999 expectations / 10 tests passed |
| New profile/fixture/hash tests | 63 expectations / 5 tests passed |
| Fresh server two-authority tests | 4 expectations / 1 test passed |
| Fresh re-signed certificate-tamper tests | 4 expectations / 1 test passed |
| Server total, across these non-overlapping checks | 1,070 expectations passed |
| Client cross-grid and existing same-owner/formal frontdoors | 444 expectations / 21 tests passed |
| Fresh client authority/certificate tests | 12 expectations / 2 tests passed |
| Client total | 456 expectations passed |
| Analytic certificate and dense regression | rational inequalities, table widths, hashes and 262,404 dense checks passed |
| Test-only Go bridge isolation | absent from untagged files; present only with `dsvert_family_reference_test` |
| Two-peer DSLite public-synthetic reference harness | all 6 family/epsilon cases passed |

Commands, from the sibling-checkout root unless otherwise specified:

```sh
# From dsVert/inst/dsvert-mpc, avoiding unrelated package-wide integration jobs:
go test -v -count=1 k2_exact_gc_multinomial_loss.go k2_exact_gc_multinomial_loss_profile.go k2_exact_gc_ordinal_loss.go k2_exact_gc_multinomial_loss_test.go k2_exact_gc_ordinal_loss_test.go

PYTHONDONTWRITEBYTECODE=1 python3 dsVert/inst/cross-grid-family-b/verify_numeric_certificate.py
Rscript -e 'pkgload::load_all("dsVert",quiet=TRUE); testthat::test_local("dsVert",filter="^crossgrid-family-b$",reporter="summary")'
Rscript --vanilla -e 'devtools::load_all("dsVert",quiet=TRUE); source("dsVert/tests/testthat/helper-cross-grid-integer.R"); source("dsVert/tests/testthat/helper-crossgrid-family-b-integer.R"); testthat::test_file("dsVert/tests/testthat/test-crossgrid-family-b-piecewise.R",reporter="summary")'
Rscript -e 'testthat::test_local("dsVertClient",filter="^(dp-(multinomial|ordinal)-grid-cross|formal-(ordinal|multinom)-frontdoor|dp-(multinom|ordinal)-grid)$",reporter="summary")'
Rscript -e 'testthat::test_local("dsVertClient",filter="^dp-multinomial-grid-cross-authorities$",reporter="summary")'
Rscript dsVertClient/tools/validate_family_b_cross_reference.R . /tmp/family_b_cross_reference_results.json
```

The main server process loaded its test file before two final security cases
were appended; those cases were executed fresh in isolated test blocks. Logs
are `/tmp/famb-server-focused-counts.log`, `/tmp/family-b-piecewise-final.log`,
`/tmp/family-b-new-security.log`, `/tmp/family-b-certificate-tamper.log`, and
`/tmp/famb-go-piecewise-final.log`. The tagged DSLite binary uses the same
family Go sources and plaintext test reference; no production handler is added.

### This family's DSLite result

Public seed 9182026; 12,000 rows; 2 independently shuffled vertical peers;
3 signed candidates; epsilon 1, 4 and 8. In every case, DP-selected candidate
3 equals the profile best, exact grid best, and nearest grid candidate to
`nnet::multinom`. Sticky replay is identical and the public release fails
closed outside the lexical test-only release mock. No standard errors are
returned. Central fit NLL=9256.610065730; exact best grid
NLL=9257.028191200. Maximum observed row error is
5.265042828e-06; maximum observed candidate-total error is
0.06318051393.

The full-domain certificate is conservative for this small 3-candidate grid:
its worst-case n*error/noise ratio at epsilon 8 is 5.470810.
Do not describe that worst-case bound as below the noise scale. The separate
certified 10,000-row/50-candidate full-domain envelope satisfies the stated
<6% ratio. The harness is a public-data reference comparison with test-only
Gamma-share noise and cache; it is **not** production PSI/MPC/joint-sampler
validation. Its complete report is in the client `tools/` directory.

### Scope and provenance

A later read-only search located the upstream Step-1 status at
`/Users/david/Documents/GitHub/dsvert-crossowner/dsVert/STATUS_V1.md`; it still
reported full-suite runs pending. Its pending runs are not counted here.
All original server tracked files are unchanged. The only existing client
file changed is NAMESPACE, with one additive export line per family. Existing
same-owner and sealed generation-one implementations remain untouched.


## Measured cost and promotion gates

The Boolean adapter uses g=18, integer cap 12,000,000; ordinal benchmark
thresholds are -8+k/16. These public benchmark choices are recorded in
`inst/cross-grid-family-b/piecewise_cost_v1.json`. Predictor formation is
outside this measurement; inputs are f100 partial-predictor shares.

| Classes | AND gates / row-candidate | Garbled table bytes | Projected table-only GB for n=10,000, grid=50 |
| ---: | ---: | ---: | ---: |
| 2 | 42,904 | 1,372,944 | 686.472 |
| 3 | 57,592 | 1,842,960 | 921.480 |
| 8 | 131,032 | 4,193,040 | 2096.520 |

Actual compiled gate inventories were measured. Bytes follow the current
engine's 32 bytes/AND, 48 bytes/OR and 16 bytes/INV; these circuits have
zero ORs and one INV. Projected traffic is arithmetic extrapolation of
**table bytes only**, excluding input OT, source/PSI, transport, reduction
and DP sampling. No whole-release network or 96-vCPU benchmark was run.
Even individual profile components exceed 2,000 ANDs: exp=11,050,
log=15,251, softplus=12,712. Moving adapter overhead to shares is insufficient
by itself. The cost target is **FAILED**, not waived.

The following gates remain closed: scalable secure profile evaluation within
the cost budget; permitted linear operations on shares; fused-producer
registration; categorical source preparation and private PSI/complete-case
proof; authenticated private guard and candidate-sum evidence; one-time share
injection; joint-DP sampling and sticky publication; real production two-peer
validation. The supplied references cannot authorize any of these gates.
See the family integration document for exact functions and ABI wiring.

## Implementation commits

Server commits on `feature/famB`:

- `fc9757d`: initial status/decision and integration boundaries.
- `f9f5bc9`: q16 Boolean loss adapters and test-only Go references.
- `e8dda08`: numeric certificates, tables, independent fixtures and R oracle.
- `3ed672e`: fail-closed server contracts and sensitivity tests.

Client commit `bbd37e9` adds the public signed frontdoors, mirrored validators,
docs and regression tests. Further test-harness/evidence commits are recorded
below. There are no pushes or thesis edits.


## Package checks and final handoff

Checks use frozen archives of server `3ed672e` and client `bbd37e9`:

```sh
R CMD build --no-build-vignettes dsVert
R CMD build --no-build-vignettes dsVertClient
R CMD check --no-tests --no-manual --no-build-vignettes --install-args=--no-byte-compile dsVert_1.2.0.tar.gz
R CMD check --no-tests --no-manual --no-build-vignettes --install-args=--no-byte-compile dsVertClient_1.2.1.tar.gz
```

Whole-package tests and byte compilation were explicitly excluded from these
checks; the focused source tests listed above ran separately. Do not interpret
these commands as a completed unrestricted full-suite run. Both packages
installed and loaded successfully. Final logs are under
`/tmp/dsvert-famb-validation/release-check-server/` and
`/tmp/dsvert-famb-validation/release-check-client/`.

Client check completed with **0 errors, 3 WARNINGs, 0 NOTEs**. All three
warning categories concern unchanged starting files:

1. Non-ASCII content in `R/ds.vertMI.R`.
2. Documentation mismatches: `analysis_contract` for `.dsvert_exact_gc_run`,
   and `.response_candidates` for `.dsvert_negotiate_dsi_chunk_size`.
3. Duplicate `analysis_id` argument in `man/ds.vertOrdinal.Rd`.

The following command from the client repository returns zero with no diff;
all six files were additionally compared byte-for-byte against `git show`:

```sh
git diff --exit-code cb26ecd -- R/ds.vertMI.R R/exact_gc_transport.R R/dsi_transport_probe.R man/dot-dsvert_exact_gc_run.Rd man/dot-dsvert_negotiate_dsi_chunk_size.Rd man/ds.vertOrdinal.Rd
```

Client commit `a92b1a3` contains the completed tagged DSLite harness and its
six-case public-synthetic result report. The final harness fixes preserve exact
f50 JSON integers (`digits=0`), assert their round trip, and avoid R int32
overflow during weighted totals by using exact doubles within the signed
2^53-1 limit. These are test-harness changes, not production transport changes.
The server package-check conclusion is appended when that process completes.


## Resumed — 2026-09-18

Read the retained status/decisions and inspected both repositories before edits.
The interrupted server changes are coherent validation/cost/integration records;
no half-written source was found. Client HEAD is a92b1a3 and clean.
The previous server check log ends during Rd usage checking and has no final
status, so it is not counted as completed. The pod endpoint is now populated;
SSH confirmed R_STACK_DONE. Continue final package checks on the isolated
/workspace/dsvert/famB/ path, retaining all numeric and production gates.

### Resumed validation setup

Frozen check inputs: server b40a90b, client a92b1a3. The following later
server commit changes documentation only: ce65a40 (secure-spline audit and
explicit production blockers). Both worktrees were clean after that commit.
The fresh pod Go family suite passed in 8.179 seconds (same 13 top-level
tests and 9 subtests, not an additional set of coverage). Command:

```sh
cd /workspace/dsvert/famB/resumed/dsVert/inst/dsvert-mpc
go test -count=1 k2_exact_gc_multinomial_loss.go k2_exact_gc_multinomial_loss_profile.go k2_exact_gc_ordinal_loss.go k2_exact_gc_multinomial_loss_test.go k2_exact_gc_ordinal_loss_test.go
```

Initial pod R checks stopped at dependency discovery, before tests: server
missing DBI/filelock/RSQLite, client missing dsVert/DSMolgenisArmadillo/DSOpal/
opalr/pkgdown. These dependencies were absent from the pod standard libraries;
a private library did not hide a usable installation. Installation uses only
`/workspace/dsvert/famB/resumed/library`; existing lanes are not modified.
Unlike the interrupted checks, the final rerun enables tests and byte
compilation. Missing dependencies are not counted as source-test failures.

### Full-suite inventory finding and correction

The first full client suite exposed a lane-introduced public-inventory
mismatch at `test-capsule-method-inventory.R:39`: the two new exported
frontdoors were absent from the frozen inventory. This is **not** a
pre-existing failure. Client commit 5cc5d92 removes those premature exports
(and roxygen export directives), keeps the implemented namespace-internal
functions and registration hooks, and documents the public-registry gate.
Both frontdoors still validate signed cross-owner contracts and fail closed.
No original client file now differs from cb26ecd; NAMESPACE is restored.
Integration must add exports and correct maturity/inventory metadata together
with the authenticated release path. The original claim of public exported
frontdoors above is superseded by this correction.

Targeted source tests passed: 891 inventory expectations, 18 authority/export
gate expectations, 318 multinomial and 23 ordinal expectations, total 1,250.
Command: `testthat::test_local("dsVertClient",
filter="^(capsule-method-inventory|dp-(multinomial|ordinal)-grid-cross.*)$",
reporter="summary")`. Log: `/tmp/famb-resumed/client-inventory-fix.log`.
A full pod check of the corrected client snapshot runs separately under
`/workspace/dsvert/famB/resumed/client-corrected/`.

### Resumed static-check findings and compute allocation

Both full checks passed installation with byte compilation, namespace
load/unload, documentation/example execution, and reached testthat. Static
findings are confined to unchanged starting files: server has the prior
undefined-helper/duplicate-local-definition code NOTE, undocumented
Gaussian/Cox/GLM objects and `privacy_unit_id` Rd mismatch; client has the
prior non-ASCII `ds.vertMI.R`, transport documentation mismatches and duplicate
`analysis_id` Rd argument. These are warnings/NOTE, not family test failures.
`git diff --diff-filter=M --name-only 4d7e6ae` (server) and the corresponding
`cb26ecd` client command both return no paths after the export correction.
The final totals remain pending until the test processes exit.

The pod exposes 96 logical CPUs but its cgroup-v1 CPU quota is 765000 us per
100000 us period: 7.65 CPU-equivalents shared by all lanes, with substantial
throttling. Do not interpret these runs as exclusive 96-vCPU performance.
The obsolete a92b1a3 client check was deliberately cancelled after exposing
the inventory defect; only its own process tree was stopped. Its corrected
5cc5d92 replacement is the final client check.

During the full server suite, the unchanged
`tests/testthat/test-dp-count-execution.R:802` source-audit test fails while
reading `test_path("..", "..", "R", "dpCountExecutionDS.R")`. This path
assumes the source-tree layout; the packaged check has no source R file at
that location. The saved failure reproduction stops at that read, before
any family function is invoked. The test file is identical to 4d7e6ae.
Keep this baseline check-layout defect separate from the corrected
lane-introduced client inventory failure; do not classify either as a NOTE.
The suites continue to collect their full results.

Two further server failures were isolated in fresh R processes without
executing family tests. The unchanged policy-ledger test at line 1157
raises `The automatic DP dataset template is awaiting one completed
authenticated padded-PSI alignment`. The unchanged synopsis-artifact file
run alone through `testthat::test_dir(..., filter="^dp-synopsis-artifact$",
package="dsVert", load_package="installed")` fails because its Gaussian
planner fixture cannot find `.dsvert_test_source_roots()`. The earlier raw
generated synopsis reproductions failed in their own path setup and are
not counted as evidence of the actual test failure. Successful isolation
logs are `logs/repro-policy-ledger.log` and `logs/repro-synopsis-file.log`
under the pod resume directory. The family tests do not mutate shared
options or namespace bindings; their sole `<<-` caches synthetic identities
in a private closure.

### Corrected client full check completed

Client 5cc5d92: `R CMD check --no-manual --no-build-vignettes
dsVertClient_1.2.1.tar.gz`, with tests and byte compilation enabled, completed
with **0 errors, 3 WARNINGs, 0 NOTEs**. Full testthat result:
**FAIL 0 / WARN 0 / SKIP 45 / PASS 25,763**; elapsed test time 1,317.467 seconds
(user CPU 578.084, system CPU 23.768). The warnings are the unchanged
non-ASCII/doc mismatches/duplicate Rd argument listed above. This full suite
includes the family and inventory regressions; do not add targeted counts
to it as independent coverage. No test filter or force-suggests override was
used in the full check. Complete logs: pod
`client-corrected/dsVertClient.Rcheck/{00check.log,tests/testthat.Rout}` under
the resume directory; local copies are
`/tmp/famb-resumed/client-check-final.log` and
`/tmp/famb-resumed/client-testthat-final.Rout`.

## Final resumed handoff — 2026-09-18

The server check did **not** complete. After recorded failures in unchanged
tests and over 80 minutes of execution, this session imposed a 90-minute
bound on that already-failing run. It was stopped at 5403.92 seconds.
This is an agent-imposed bound, not a successful check, a test-framework
summary, or a reviewer waiver. No final server pass/fail/skip counts or final
R CMD check status are available. Its partial static results are two WARNINGs
and one NOTE; its recorded test problems are separately preserved.
There are 13 unique saved problem locations, some reported repeatedly;
this is not a count of failed expectations. Original server files and tests
are unchanged from 4d7e6ae. No family problem location was reported before
termination. The earlier focused family checks remain the completed server
family evidence; an unrestricted passing full-server suite is an OPEN gate.

The complete corrected client check, incomplete server check, test outputs,
and two independent baseline failure reproductions are committed under
`inst/cross-grid-family-b/validation_resumed/`. `summary.json` records the
exact completed/incomplete distinction, snapshots, commands, counts and
remaining gates. All jobs started by this session have stopped; neither the
server runner nor its test process remained after termination. Other lanes'
processes were not stopped.

Final implementation commits remain server 3ed672e (with numeric/circuit
commits f9f5bc9 and e8dda08) and corrected client **5cc5d92**; client reference
harness is a92b1a3. Resumed evidence commits are b40a90b, ce65a40, 4be280c,
ae013ee and d299b75, followed by this final evidence handoff commit.
No original server or client tracked file differs from its starting commit.
The two client exports are deferred, with their functions retained internally.

**Stop state: genuinely blocked for production promotion.** The certified
Boolean adapter fails the binding cost target; the retained ring/spline
comparator is unsafe to substitute; fused-producer and public-registry wiring
remain external integration gates. Full server validation also remains open.
See `BLOCKED_MULTINOMIAL.md` and `INTEGRATION_MULTINOMIAL.md`. No epsilon/delta/cap,
same-owner route, sealed generation-one route or thesis was changed. No push.
