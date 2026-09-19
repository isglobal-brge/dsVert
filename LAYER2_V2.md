# Layer 2: secure integer computation and authenticated persistence

Component gates and all twelve required n2000 API releases pass. Additional
K3/K5 owner topology gates are still running and are not claimed complete.

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

## Required-size real release gate — PASS

All twelve required releases pass: n2000/p6/grid2/K2, two independent signed
grids per family and epsilon in {1,4,8}, delta=2^-100. Each uses the actual
DataSHIELD client API, matches the complete authenticated integer DP vector
and selected candidate against the production-seeded oracle, and passes
fresh-process exactly-once/replay/tamper checks on both authorities.

The complete six-cell logs are `inst/cross-grid-v2/validation-{family}-e{epsilon}.log`
with matching before/after `-source-check.log` evidence. The aggregate validator
passes all 120 unique keys and all twelve real-release verification pairs.
[LAYER3_V2.md](LAYER3_V2.md) records selection statistics and all API times.

An earlier n2000 binomial attempt matched its vector but subsequently rejected
a stale worker-bundle manifest in the cold process. That excluded attempt is
retained in `dslite-n2000-before-cold-bundle.log`; the repaired bundle was used
for the full successful matrix. Neither that attempt nor small smoke/topology
probes count toward the required twelve.

## Additional source-owner topology gates

Binomial K5 **PASS**, n2000/p6/grid2/epsilon4: all five owners align and sign;
the real two-authority API release matches the complete integer oracle
vector and passes cold exactly-once/replay/tamper checks. It selects
candidate2, the exact best, with zero loss gap; API time is **3226.806 s**.
`inst/cross-grid-v2/topology-binomial-k5.log` and its source-check log retain
the result and all 274 before/after frozen R/binary/harness checks;
`topology-k5-support.sha256` identifies those inputs.

This is the explicitly smaller K5 envelope permitted by clause 7. Poisson
K5 and both n10000/p10/grid50 K3 releases are still running; no completion
is claimed for them. Reproduce the K5 sequence with
`run_k5_after_matrix_pod.sh` after the complete selection matrix.

Poisson K5 **PASS** at the same n2000/p6/grid2/epsilon4 envelope: complete
integer DP-vector oracle equality, cold exactly-once/replay/tamper checks,
and all 274 before/after source hashes pass. API time **3810.832 s**; selected
candidate2 equals exact-best2 with zero gap. Evidence: `topology-poisson-k5.log`,
its source-check log, and `topology-k5-queued.log` with `K5_TOPOLOGY_POD_DONE`.
Both K5 family gates are complete. Both full-grid K3 gates remain running.
