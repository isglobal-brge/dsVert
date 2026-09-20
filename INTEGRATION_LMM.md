# Cycle42: batch authenticated normalization and conversion exchanges

LMM and both GLMM source graphs now use up to 128 rows per complete-case
normalization stage, bounded by the existing 512-Kibit typed-input limit, and
256 coordinates per Ring128-to-Ring192 conversion chunk. GLMM q0 outcome
normalization uses 256 rows and reuses its immutable public program per shape.
The default router/conversion/outcome builders retain 16/32/32 batching for
other callers, including GEE. No GEE-owned source or certificate is changed.

At n2000/p3 this reduces normalization stages from 125 to 16 and conversion
chunks from 313 to 40; each conversion chunk retains its dual-ring mask,
masked opening and private carry/sign protocols. GLMM outcome exchanges fall
from 63 to 8. Each batch still draws fresh masks/OT coins and authenticates
its source, session and attempt. Exact integer expressions, rounding, caps,
epsilon/delta, complete-case gaps and sticky validity are unchanged. Public
stage bounds bind the new schedule, so graph/receipt identities change;
old stores and frozen releases must not be reused or rewritten.

Fresh native baseline and patched snapshots pass complete LMM/binomial-GLMM/
Poisson-GLMM source-to-loss oracle checks and recovery. New regressions exercise
two full batches plus tails, bilateral fresh-attempt and unilateral persisted
recovery, cold replay, and byte-equal reconstructed routing/outcome outputs
against the legacy schedule. Focused R lifecycle/admission/Gaussian fallback
checks pass (12 tests, 204 assertions). All four Go1.25.7 runtimes are rebuilt.
Evidence: ../integrator-evidence/cycle42-20260920/.

This is batching and native equality evidence, not a new n2000 serialized-RPC
capacity result. A fresh signed n4/K2 recovery smoke is running separately.
The fleet manifest must be repinned to this committed runtime for the capacity
rerun; the 256GB/21,600-second ceiling is unchanged. Four simples remain
promoted at their original pair; no heavy promotion is asserted here.

---

# Cycle20: reuse immutable public normalization and lift programs

The private routing graph caches normalization programs by their complete public
source text. At n2000 this compiles the identical 16-row program once per
per-authority graph instead of 125 times. A partial final chunk has its own
program. Cache lifetime is one sequential graph; owner inputs, masks, wire
labels, OT streams, sessions and durable outputs are not cached. Every stage
still checks current source shape and uses its existing attempt domain.

The LMM signed-limb lift similarly compiles once for full 32-coordinate chunks
and once for a tail within each stage attempt. No integer expression, rounding,
cap, epsilon/delta, stage ID, source/profile hash or receipt rule changes.
This does not share programs between variance branches.

Fresh native baseline and modified snapshots both pass 13 selected LMM/router
checks, including a new 36-row repeated/full/tail normalization fixture with
bilateral and unilateral normalization recovery, and an 11-cluster repeated
lift fixture against independent integer oracles. Cold replay, source rejection,
ML arithmetic and actual spool workers pass. This is local Go1.25.7 native
component evidence, not a signed n2000 release or measured wall-time speedup.
Shared GLMM regression checks also pass 10 selected native tests,
including both outcomes, private source validation and recovery. Four platform
runtimes were rebuilt from the verified modified snapshot with Go1.25.7.
Full authenticated relay batching, signed optimized-source lifecycle proofs,
full paired suites and the capacity envelope remain pending.

The binding release methodology is four real epsilon8 jobs per heavy family:
K2/K3/K5 plus one K2 recovery/cold/tamper job, one per fleet pod. Selection grids
are oracle-only; measure capacity once per family against 256GB/6h separately.
Historical matrices and ceilings below are superseded by that methodology.

Evidence: workspace `integrator-evidence/cycle20-20260920/`.

---

# LMM sufficient-statistic integration — not a release capability

`registerGroupedLMM()` returns the new typed components. `LegacyCompile` is
only the preceding q64 prototype and must NOT evaluate contracts carrying
`grouped-lmm-stats-f264-q64-v2`. Both R sides now sign that profile and exact
f100 dot semantics. Source f50/Ring128 ABI, variance domain, epsilon/delta,
output caps and patient sensitivity are unchanged. No source read is enabled.

Required ordered wiring:
1. Authenticate the two source/PSI/complete-case receipts. Privately validate
   f50 bounds, binary live flags and grouping capacity; mask every column.
   Pack `(live*f50, live*x*f50, live*y*f50)` and run the primitive permutation
   ONCE into fixed public B-slot blocks. Bind all primitive chunks to the
   signed schedule, including padding and the private validity conjunction.
2. `Prepare(plan, rows)` makes local cluster sums. `operands` traverses the
   candidate-independent row and cluster-sum upper triangles in batches <=1024.
   Pass each pair batch to `registerGroupedExactArithmetic()` and call
   `accumulate` only after consuming its authenticated receipt once. The
   component does not implement a durable chunk store or detect duplicate
   accumulation: the trusted fused adapter must do so before dispatch.
3. `PrecisionCompile` privately selects q64 lambda from the f50 count column
   and yields a private validity bit. Multiply each between-cluster-sum moment
   by lambda with the exact OT component; `PrecisionShares` forms the f164
   precision Gram shares with the public inverse coefficient.
4. `LiftCompile` (1..32 entries) supplies the carry-correct high Ring192 limb
   for each precision Gram entry. Retain the original low share; do NOT
   zero-extend shares. `GridShares` multiplies public f100 beta products and
   accumulates in two Ring192 limbs (Ring384), with zero arithmetic error.
5. `FinalCompile` clamps/rounds each cluster/candidate at f264 exactly once.
   Bind its cap to U_j and carry ALL private source/count/chunk validity into
   its private gate. Sum quantized shares, then use the Step-2 authenticated
   joint-noise, sticky-ledger and release-evidence interface. Final boundary
   requires 22,824 gates / 214,896 table bytes for the tested g16/U999 shape;
   no runner cap is raised. Measure the actual signed shapes before admission.
6. Add full process-isolated R/DSLite lifecycle and the 3x3 full-release matrix,
   then admit a measured <=110 GB, <=4 h capacity and connect the client reader.

The reference equation, exact lift proof and error bound are in
NUMERIC_CERTIFICATE_GROUPED.md. The Go independent residual oracle and pure-R
limb oracle agree. Those tests are not an authenticated protected release.
Neither full-release capacity nor source/primitive-to-DP integration is claimed.

## Addendum 4 preflight — 2026-09-18

The binding ceiling is **110 GB / 4 h**. No release capacity is admitted;
all requested shapes are rejected by current prototype contracts. See
INTEGRATION_GROUPED.md's Addendum 4 section and
`inst/grouped-validation/addendum4-preflight.json` for the unmeasured matrix
and exact prerequisites. Component timings do not establish release capacity.
