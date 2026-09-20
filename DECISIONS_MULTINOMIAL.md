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

## Implementation and review decisions

7. Pin `exp_profile(0)=65536` explicitly. The uncorrected last quadratic
   produces 65535; that could make a max-shifted sum smaller than one and
   underflow the bounded log argument. The profile hash covers this endpoint.
8. Round directly from f100 to q16. A q64 intermediate can change a q16 tie;
   fixtures cover halfway values plus/minus one f100 unit and both signs.
9. Require exactly two participating custodians and equality with the two
   compute/noise authorities. Requiring two compute peers alone was insufficient.
   Server/client tests reject extra custodians and mismatched authority pairs.
10. The standalone Boolean adapter fails the cost target even before considering
    source/PSI/noise traffic. Keep it as certified equality/cost evidence and
    keep all production release seams disabled. A cheaper secure evaluator
    and share-based linear accumulation are prerequisites for promotion.


## Resumed — 2026-09-18

Preserve the completed profile and certificate rather than changing signed
numerics merely to meet a cost target. Verify the existing ring/spline route
before claiming it can replace the measured Boolean adapter. The now-ready
pod is available for final checks; earlier endpoint failures remain historical.

The retained arithmetic-share alternative is not eligible for direct reuse.
`inst/dsvert-mpc/k2_distributed_cmp.go` and
`k2_distributed_cmp_ring127.go` explicitly document quarter-ring mask leakage
and differential-wrap comparison failures;
`TestQuarterRingDCFMaskHasDifferentialWrapCounterexample` and
`TestQuarterRingDCFMaskLeaksCoarseRange` record regression counterexamples.
`k2_spline_protocol_ring127.go` invokes this comparison in its indicator path.
Changing the ring width or constraining the input does not eliminate the
mask-distribution leakage. Its runtime-generated linear tables also do not
implement the signed quadratic profile. Do not wire it as a cheaper family
backend. A certified secure shared evaluator must arrive through the common
primitive/integration work, with matching table/rounding and fresh cost proof.

## Public inventory correction from full check (2026-09-18)

The full client suite exposed that the two additive NAMESPACE exports were
not represented in the frozen capsule inventory/maturity registry. Remove
those premature exports while retaining both implemented functions, docs,
validators, registration hooks and tests inside the namespace. Integration
must add public exports together with accurate inventory/maturity entries
and authenticated release wiring. Do not label the disabled routes promoted
or modify sealed generation-one inventories in this lane. A new regression
asserts that both functions exist, are unexported and have release disabled.
