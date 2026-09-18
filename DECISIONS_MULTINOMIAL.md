# Multinomial decisions

## Retained decisions

Use 2..8 public classes, a signed reference class with score zero, and one
signed coefficient vector per other class. Sum per-owner f100 predictors
before rounding. Preserve f50 feature/coefficient encoding, per-class L1<=16,
component magnitude<=8, canonical grids, both custodians' signatures,
capacity padding, private alignment and complete-case masks. Registration
describes a family; it cannot authorize a release. Plaintext row references
are test-only and never registered as worker operations.

## Binding arithmetic amendment (2026-09-18)

1. Replace the protected q64 exp/log circuit with public, certified
   low-precision piecewise-polynomial tables. The numeric profile identity
   changes; old signed profiles must fail reconstruction under the new contract.
2. Subtract the private maximum of all class scores, including the reference
   zero, before evaluating exponentials. This preserves log-sum-exp while
   bounding its exponential sum and permits a certified tiny negative tail.
3. Derive integer caps from the exact mathematical upper bound plus the
   certified profile/rounding allowance. Explicit integer clamping remains
   mandatory. Approximation alters utility, never privacy parameters.
4. Keep single family registration functions and fail-closed release seams.
   The parallel integration session owns protected source materialization,
   private PSI/complete-case evidence, secure candidate reduction, joint
   noise, attestation and sticky semantic publication.
5. Measure the current Boolean engine honestly. A correct, certified circuit
   does not imply satisfaction of the 2,000-AND target or production readiness.
   Any unmet performance gate remains explicit.
6. Keep public-synthetic DSLite reference tests clearly distinct from production
   MPC validation. Test-tagged plaintext evaluation must be absent from a
   production build and unreachable through registered commands.
