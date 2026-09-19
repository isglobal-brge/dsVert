# Clause 5 component measurements — 2026-09-18

PASS scalar gate; full-release admission NOT MEASURED. The historical
whole-cluster traffic blocker is withdrawn, not re-applied to this design.

Pod: R_STACK_DONE verified, /workspace/dsvert/grouped/clause5. Fresh masked
outputs over authenticated encrypted two-peer net.Pipe with checked OT.
Traffic counts writes in both directions. Every chunk has 32 scalar values
plus one private aggregate validity bit. Source and runner caps unchanged.

| Profile | AND/value | Chunk bytes, both directions | Protocol seconds |
|---|---:|---:|---:|
| softplus | 2517 | 2,680,732 | 1.110591 |
| exp | 4454 | 4,665,337 | 1.592850 |
| exp_negative | 4454 | 4,665,335 | 1.304890 |
| log | 2373 | 2,533,205 | 1.093744 |
| sigmoid | 2371 | 2,531,156 | 1.013385 |
| sqrt_variance | 3067 | 3,244,256 | 0.985213 |
| inverse_sqrt_variance | 3308 | 3,491,184 | 0.694747 |

Both valid boundary batches and a batch with an invalid lower-bound argument
pass integer-oracle equality. Invalid input zeros every scalar and validity.
For softplus, compact and legacy encrypted runs reconstruct identical values;
compact uses fewer bytes. Topology, purpose and framing mode are digest-bound.

The first 32-value probe failed its exp cost assertion because conditional
array writes caused unnecessary compiler multiplexing. Scalar masking before
array writes removes that overhead without changing integer semantics. The
final seven-profile pod probe passes; no threshold was raised.

No (n,grid) point in {2000,4000,10000} x {16,32,50} is admitted by these
measurements. They exclude private routing, source/PSI, exact secure products,
rescaling, clipping, authenticated chunk persistence, joint noise and sticky
release. Multiplying chunk bytes by n*grid*Q is not a measured full release.
The Q=5 GLMM workload additionally needs per-cluster stable log-sum-exp.
See CLAUSE5_ARITHMETIC_GROUPED.md for the unresolved arithmetic interface.

Machine-readable measurements/source hashes: inst/grouped-validation/clause5-components.json.
Final command: DSVERT_GROUPED_SCALAR_PROBE=1 go test -run
'^TestGrouped(Scalar|ShareBlock|ClauseFive)' -json -count=1 -timeout=5m .
Pod log: /workspace/dsvert/grouped/clause5/scalar-context-final.jsonl (146.310 s).
