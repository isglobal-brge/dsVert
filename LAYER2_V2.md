# Layer 2: secure integer computation and authenticated persistence

Component gates pass; the n2000 API matrix and additional owner topologies
are still running. This report does not claim those pending releases.

## Secure arithmetic

`inst/cross-grid-v2/worker-targeted-mac.log` records actual two-peer
`net.Pipe` execution for both families, valid and invalid private records,
and bit-for-bit integer-oracle equality. Joint-noise composition is tested
with the production reference mechanism. Durable worker tests use the actual
CLI staging and transcript. Purpose/admission tests reject malformed public
plans. `sticky-worker-mac.log` additionally verifies identical masked output
under fresh sharing/session randomness with the same semantic seed.
`fused-r-mac.log` records 288 full-f100 fixtures checked by independent R
integer limbs. The Go candidate-tail regression covers 35 rows, 10 candidates
and three owners (`oracle-chunks.log`).

## Authenticated lifecycle

`inst/cross-grid-v2/dslite-poisson-smoke.log` is a clean real two-authority
API release at n4/p6/grid2/epsilon4. The harness deliberately interrupts after
durable secure batches, retries in a new computation session, compares
independently planned production sticky seeds/contracts, and verifies the
entire raw integer DP vector against the oracle. The successful retry takes
201.144 seconds under concurrent Mac benchmark load.

Fresh R processes then call server functions directly (no DSI for this
layer): authenticate the signed contract/schema; read snapshots of the actual
pre-compaction private records; verify injection into the original aggregate
and repeated identical reads; replay identical writes; reject a changed
semantic key; and reject a MAC-tampered record through the public transcript
boundary with a constant error. Both authorities pass. Snapshots preserve
the production tombstone rules; this is a fresh-process persistence test,
not a claim that published compacted records can be restored in production.

The two earlier binomial n4 logs establish vector equality but retain their
subsequent harness failures explicitly; they are not clean campaign passes.
The final matrix repeats cold-process checks for both families at each epsilon.

Targeted final admission/no-fallback tests: server 338 assertions and client
322 assertions, zero failures/errors (`noise-policy-targeted.log` in the
server and `noise-grid-targeted.log` in the client). Shared client exact-noise
and Synopsis adapters have 98 passing targeted assertions. Full-package
checks remain a separate final gate.

Reproduction: run the source-tree `validate_dslite.R` via
`Rscript -e 'source("inst/cross-grid-v2/validate_dslite.R")' ..` from dsVert,
with `DSVERT_GRID_VALIDATION_FAMILY=poisson`,
`DSVERT_GRID_VALIDATION_COLD=1`, and `DSVERT_GRID_VALIDATION_INTERRUPT=1`.
The private state parent must be mode 0700 and outside temporary and installed
library trees. No seeds, private shares or noise-free protected losses are
written to committed evidence.

Additional integration evidence (2026-09-18T19:07Z):
`topology-k3-small.log` records a real three-owner, two-authority binomial
n4/p6/grid2/epsilon4 API release matching the complete production-noise oracle
integer vector. `fused-alignment-targeted.log` verifies that grid-only raw
source-share reads are impossible before the exact matching authenticated
digest-gate terminal, and rejects changed artifacts/projections before reads.
This specialization retains the independent fused per-row alignment guard.
`relay-admission-targeted.log` includes the regression that a fresh DSLite
session remains admissible to the closed Synopsis authorization state.
These small/targeted gates do not replace the required n2000 or full topology
releases.

Required-size integration progress (2026-09-18T21:23Z): the first n2000, p6, grid2, binomial epsilon1 API release matched the complete oracle vector (`dslite-n2000-before-cold-bundle.log`). A subsequent fresh-process check exposed a stale deployment checksum manifest, correctly rejected before contract admission. The complete binary bundle was repaired; direct cold signed-profile admission at n2000 now passes for both families. This incomplete cell is retained as extra evidence and excluded from the final 120/12 matrix.


Qualifying n2000 progress (2026-09-18T21:58Z): both entries below pass complete
integer DP-vector equality through the real DSLite client API and the subsequent
fresh-process exactly-once, replay and tamper checks. They count toward the
required matrix; the complete six-cell evidence validator has not yet passed.

| Family | Epsilon | Instance | API seconds | Evidence |
|---|---:|---:|---:|---|
| binomial | 4 | 1 | 2932.752 | `inst/cross-grid-v2/dslite-n2000-binomial-e4-first.log` |
| poisson | 1 | 1 | 3390.267 | `inst/cross-grid-v2/dslite-n2000-poisson-e1-first.log` |

Each uses n=2000, p=6 split 3/3, two signed candidates and delta=2^-100.
The required count is 2/12; these individual results do not establish the
20-instance selection statistics, other epsilon cells or K3/K5 topology gates.

The recovered binomial/epsilon1/instance1 also passes both gates in 2838.057 s
(`inst/cross-grid-v2/dslite-n2000-binomial-e1-first.log`), bringing the required
real-release count to **3/12**. The earlier failed cold-deployment attempt
remains excluded.

Binomial/epsilon4 now has both required independent real releases with both
verification markers (`inst/cross-grid-v2/dslite-n2000-binomial-e4-two-real.log`).
Instance2 takes 2767.322 s. Required real-release progress is **4/12**.

Poisson/epsilon1 now also has both real release and cold-lifecycle matches
(`inst/cross-grid-v2/dslite-n2000-poisson-e1-two-real.log`). Instance2 takes
3247.900 s and its nonzero DP selection gap does not affect integer oracle
equality. Required real-release progress is **5/12**.

Binomial/epsilon1 completes both real release and cold-lifecycle matches in
`inst/cross-grid-v2/dslite-n2000-binomial-e1-two-real.log`; instance2 takes
2801.709 s. Required real-release progress is **6/12**.

Poisson/epsilon4/instance1 passes both required gates in **3782.294 s**
(`inst/cross-grid-v2/dslite-n2000-poisson-e4-first.log`), bringing real-release
progress to **7/12**. This cell is not yet complete.

Binomial/epsilon8/instance1 passes both gates in **3216.212 s**
(`inst/cross-grid-v2/dslite-n2000-binomial-e8-first.log`). Required real-release
progress is **8/12**; the full cell remains pending.
