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
