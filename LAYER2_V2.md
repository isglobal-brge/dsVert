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
