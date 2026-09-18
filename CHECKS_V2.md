# Step-2 package checks — in progress

Full suites were run once on the pod. Fixture and documentation corrections
were then checked in targeted files, as required by the validation layering.
No second full-suite pass is claimed.

| Check | Observed result |
|---|---|
| Full server testthat | 12,944 passes, 24 failures, 25 skips, one warning |
| Full client testthat | 25,476 passes, four failures, 45 skips, zero warnings |
| Full Go suite | 977 listed top-level tests; 31 failures in existing formal Cox/GLM tests; 8595.384 seconds. Not green. |
| Corrected server packaging, `R CMD check --no-manual --no-tests` | Zero errors/warnings; one pre-existing NOTE |
| Corrected client packaging, same command | Zero errors; two pre-existing warnings pending the prepared patch |

The full R logs are `inst/cross-grid-v2/check-{server,client}-tests-first.log`.
The corrected scopes below account for the recorded R failures; counts overlap
between reruns and must not be added to the full-suite counts.

| Corrected scope | Passing assertions | Evidence log |
|---|---:|---|
| Server registered aggregate inventory | 145 | `remote-inventory-targeted.log` |
| Count source-path audit, Gaussian mock, grid callr source discovery | 468 | `check-fixtures-targeted.log` |
| Installed Synopsis artifact | 57 | `check-fixtures-installed-first.log` (other failures in that log were subsequently corrected) |
| Installed Synopsis exact-GC, execution, release, source gate/wrappers, START | 531 | `synopsis-installed-corrected-targeted.log` |
| Installed Synopsis execution safety | 18 | `check-fixtures-installed-first.log` |
| Installed legacy source contract, complete exact transport, typed blob | 1,871 | `final-server-failures-targeted.log` |
| PSI and remote-surface fixtures | 191 | `psi-check-corrected-targeted.log` |
| Client remote construction inventory and typed retry audit | 99 | Client `check-inventories-targeted.log` |

All paths above are under `inst/cross-grid-v2` in the indicated package.
The original full-suite transport inactive-operation error did not recur in
the complete installed transport-file rerun. No timeout or lease was relaxed;
the original failure remains in the evidence.

The legacy source-contract hash correction is independently grounded in the
unchanged output of step-1 snapshot `15e1de2` and pre-materialiser `89ee9be`.
It does not change production release keys. The corresponding baseline,
current and corrected logs are retained.

The server NOTE concerns existing duplicate local `normalize` formals and
optional formal typed-blob hooks. The relevant normalization definitions are
unchanged from step 1; `R/typedBlobTransportDS.R` is byte-identical to step 1.
The two remaining client warnings concern an MI print literal containing a
Unicode multiplication sign and duplicate ordinal argument documentation.
The exact packaging-only patch is in the client evidence directory; applying
it awaits the user's decision because other-family edits were prohibited.

`final-check-inputs.sha256` identifies the current 1,497 package input files.
The full Go source and four worker binaries are unchanged from the original
full-suite archive. Later changes in this check cycle affect tests, inventories
documentation and packaging exclusions only. Neither package version nor NEWS was changed.


The full Go run has finished. Its non-verbose log does not separate successful
from skipped tests, so no invented pass count is supplied. The unchanged
snapshot's `go test -list '^Test' ./...` lists 977 top-level tests.
`full-go-tests-first.log` retains all 31 failures; none names a new cross-grid
test. `full-go-failure-classification.json` lists every failed test.

- Four formal GLM failures match top-level failures already recorded in
  STATUS_V1: closed-selector expectation, loader text scan, schedule-tail
  reconstructed coordinate, and Phase20 inbound ordering. Their source/tests
  are unchanged from step 1. Timing-dependent subcase differences are not
  claimed equivalent or repaired.
- Twenty-six Cox failures originate in existing R schema-signature fixtures.
  The public-schema-only probes reproduce the same rejection on frozen
  15e1de2 and the full-check snapshot; the compiler fixture is checked for
  K=2,3,5. Logs: `go-cox-{step1,current}-{public,compiler}-schema.log`.
  This proves baseline reproduction, not a diagnosed or repaired root cause.
- The remaining Cox Phase1 CLI inventory test expects three entries although
  both step 1 and current source contain the same eleven entries. The exact
  unchanged inventory is included in the classification JSON.

These are recorded existing-suite failures, not a clean full Go pass. No
unrelated formal Cox/GLM implementation or test expectation was changed to
suppress them. Targeted new-route evidence remains separate in LAYER2_V2.md.

Final server packaging refresh: `check-server-packaging-final.log` again
reports **zero errors, zero warnings, one identical pre-existing NOTE**.
`recheck_server_packaging_pod.sh` rebuilds the corrected archive and runs
`R CMD check --no-manual --no-tests`; all 1497 input hashes match. The new
CHECKS_V2 report is excluded alongside the existing development reports.
The rebuilt server tarball includes the last corrected test fixtures.
