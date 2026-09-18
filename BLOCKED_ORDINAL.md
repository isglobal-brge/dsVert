# Ordinal promotion blocked — 2026-09-18 resumed audit

The family implementation, certified q16 profile, Go circuit/reference,
pure-R oracle, signed validators, caps, client and public-synthetic two-peer
reference harness are retained. This is a production-promotion blocker, not
a numerical equality failure or a tool-quota interruption.

## Blocking evidence

1. The measured Boolean adapter exceeds the binding 2,000-AND / approximately
   30-GB release target. `inst/cross-grid-family-b/piecewise_cost_v1.json`
   contains actual compiled inventories. Even component profiles exceed the
   target: exp 11,050 ANDs, log 15,251, softplus 12,712. Moving only linear
   adapter operations to shares does not resolve this.
2. The retained Ring63/Ring127 spline backend cannot safely replace it.
   `k2_distributed_cmp.go` and `k2_distributed_cmp_ring127.go` document
   quarter-ring mask leakage and differential-wrap failures. Existing tests
   `TestQuarterRingDCFMaskHasDifferentialWrapCounterexample` and
   `TestQuarterRingDCFMaskLeaksCoarseRange` supply counterexamples. This
   requires a secure shared primitive redesign, not family registration.
3. The parallel fused producer must supply categorical source preparation,
   private alignment/complete-case evidence, correct share widening and
   predictor summation, authenticated candidate reduction, guard handling,
   joint-DP injection and sticky publication. These are not supplied by a
   plaintext reference, contract state string or numerical certificate.

## Conditions for resumption and promotion

Supply a two-authority secure profile evaluator that matches the pinned
quadratic tables and rounding, with measured cost satisfying the binding
budget. Wire the exact boundaries in `INTEGRATION_ORDINAL.md`, then run
protected two-peer tests with malicious metadata/guard rejection and replay.
The public-synthetic DSLite reference harness is not that production test.
Neither lower privacy parameters nor a plaintext production fallback is an
acceptable workaround. Both release registrations remain disabled.

The supplied pod is now ready; tools and compute availability are not blockers.
Package check results and final commits are recorded in `STATUS_ORDINAL.md`.
