# Grouped revised resource gate — 2026-09-18

Scalar gate PASS; composed release traffic gate FAIL for the measured kernels
under the proposed cluster/candidate traversal. No full release was executed.

Measured on the R_STACK_DONE pod (Go 1.25.7, linux/amd64), using authenticated
encrypted net.Pipe transport and fresh output masks. Both endpoints' writes
are counted. Source file hashes match the final local sources byte-for-byte.
All nine public empty-cluster fixtures reconstructed correctly, including
private validity and GEE's public bread/meat shifts. No protected data entered
these probes. All compiled kernels stayed below 32M gates and existing runner
input/source caps.

| Profile | Rows/chunk | M gates | Measured two-way MB/chunk | Mandatory tables GB at 10000 x 50 | Compile s | Protocol s |
|---|---:|---:|---:|---:|---:|---:|
| lmm | 32 | 2.001 | 27.325 | 289.408 | 4.73 | 2.58 |
| binomial_glmm | 16 | 1.415 | 20.453 | 442.676 | 28.29 | 2.31 |
| poisson_glmm | 16 | 1.952 | 27.739 | 603.140 | 23.89 | 3.00 |
| binomial_gee_independence | 8 | 11.767 | 163.731 | 7243.389 | 48.30 | 11.39 |
| binomial_gee_exchangeable | 8 | 11.804 | 164.171 | 7261.789 | 44.20 | 15.41 |
| binomial_gee_ar1 | 8 | 11.807 | 164.232 | 7264.877 | 39.31 | 17.09 |
| poisson_gee_independence | 8 | 11.870 | 165.144 | 7306.125 | 32.91 | 14.30 |
| poisson_gee_exchangeable | 8 | 11.906 | 165.584 | 7324.525 | 34.62 | 16.87 |
| poisson_gee_ar1 | 8 | 11.909 | 165.645 | 7327.613 | 27.69 | 13.51 |

Decimal MB/GB. The last traffic column is an exact payload lower bound for
repeating each measured kernel ceil(10000/B)*50 times, NOT measured whole-release
traffic. It excludes routing, dot formation, source transport, noise and ledger.
Multiplying measured chunk wire traffic is separately and explicitly labelled
as an extrapolation in revised-cost.json. Times are observed chunk times,
not a wall-clock claim for a parallel complete release.

LMM/GLMM consume a shared predictor/residual, so p=10 belongs to the unmeasured
upstream dot stage. GEE probes only the current three-predictor domain; they
make no p=10 support claim. The hypothetical repetition also exceeds current
R cluster/candidate admission limits. It is a resource diagnostic, not a newly
accepted signed schedule. LMM uses its Go maximum B=32 (R currently B<=16).
The exact public probe parameters are in k2_exact_gc_grouped_loss_cost_test.go.

These lower bounds already exceed 60 GB, so a successful scalar test cannot
justify enabling a release. Compact transport framing (upstream 0006f1a) can
remove redundant framing but not the garbled-table payload counted here.
A different composed arithmetic implementation and real full-size validation
are needed. Neither raising caps nor further scalar threshold resets solve
this measured workload problem.

The initial measurement harness incorrectly expected GEE's public shifts to
vanish for empty padded clusters. Corrected that test expectation; no kernel
behavior changed. The unsuccessful probe remains at cost-initial-fixture.log
on the pod and is excluded from the authoritative table. The final successful
campaign took 383.42 seconds including all nine subtests.

Reproduce from inst/dsvert-mpc:

```
DSVERT_GROUPED_COST_PROBE=1 go test -run '^TestGroupedRevisedGateMeasuredCosts$' -v -count=1 -timeout=30m .
```

Evidence: inst/grouped-validation/revised-cost.json and revised-cost.log.
The independent scalar/certificate and synthetic fit comparisons are in
revised-validation.json and revised-synthetic-comparison.json. Broad Go and
prior-snapshot R checks are recorded separately in revised-check-progress.json;
that progress snapshot is not a completed regression or R CMD check pass.
