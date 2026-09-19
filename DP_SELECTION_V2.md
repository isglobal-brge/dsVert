# Layer 3 — DP selection

IN PROGRESS. The authenticated production release route is implemented.
Small real two-authority API releases already reproduce the production-noise
oracle bit for bit (see LAYER2_V2.md), including a K3 diagnostic. The n2000
120-selection/12-release campaign is running. Validated per-cell results are
reported below; the complete matrix is not yet claimed.

The binding remaining matrix is 20 sticky-independent signed grids per family
per epsilon in {1,4,8}, n=2000, delta=2^-100 on the same-noise oracle path,
followed by at least two real two-authority releases per (family,epsilon)
through the two-peer DSLite client harness (12 releases), bit-for-bit equal to
the corresponding oracle releases. Test-only nonlinear circuit runs are not
counted as any of those releases.

The two family-specific fused-kernel/joint-Laplace tests at epsilon=4 are small
synthetic net.Pipe composition tests. They are neither selection statistics nor
DataSHIELD wiring releases and are not counted toward either validation matrix.


Validated completed cells (remaining two cells pending):

| Family | Epsilon | Distinct grids | Real API matches | Selection agreement | Mean loss gap | Maximum loss gap |
|---|---:|---:|---:|---:|---:|---:|
| binomial | 1 | 20 | 2 | 16/20 | 2.68316 | 14.4925 |
| binomial | 4 | 20 | 2 | 20/20 | 0 | 0 |
| poisson | 1 | 20 | 2 | 11/20 | 31.2351 | 73.8808 |
| poisson | 4 | 20 | 2 | 16/20 | 14.2878 | 75.0381 |

Evidence: `inst/cross-grid-v2/validation-binomial-e4.log` and its
`validation-binomial-e4-source-check.log`. Both real releases pass the
fresh-process lifecycle checks. Before/after frozen-harness hashes match;
all twenty artifact keys are distinct and no run error occurs. Geometry is
n=2000, p=6 split 3/3, two candidates, delta=2^-100. Gaps are differences
between noise-free certified integer objectives divided by 2^16. This
conditional synthetic result does not establish utility for all admitted grids
or accuracy of a continuous estimator.

The second cell is retained in `validation-poisson-e1.log` and its matching
source-check log under `inst/cross-grid-v2`. All twenty keys are distinct;
its two real releases pass both equality and fresh-process lifecycle gates.
The reported mean uses the per-instance decimal precision retained in JSON.

Binomial/epsilon1 is also complete (`validation-binomial-e1.log` and its
source-check log). Across these three cells, all 60 artifact keys are distinct,
all requested geometries match, and all six real releases have both required
verification markers. The remaining epsilon8 binomial and epsilon4/8 Poisson
cells are still running.

Poisson/epsilon4 is complete (`validation-poisson-e4.log` and its source-check
log). All 80 keys across four complete cells are distinct; geometry, two real
release equalities, cold lifecycle checks and before/after hashes pass. Its
mean loss gap is 14.287785 at retained JSON precision. Both epsilon8 cells
remain in progress.
