# Ordinal decisions

## Retained decisions

Use 2..8 signed ordered classes, zero intercept, normalized-feature slope
L1<=8, threshold magnitudes<=8 and adjacent gaps>=1/16 in both raw and f50
encoded domains. The zero intercept fixes the threshold/location ambiguity.
These are new cross-owner semantics; same-owner ordinal code is untouched.

For an interior class with u=c_k-eta, l=c_(k-1)-eta and d=c_k-c_(k-1), retain
`softplus(u)+softplus(l)-u-log(1-exp(-d))`. Do not subtract two rounded private
sigmoids. The threshold gap is signed public metadata, so its correction can
be prepared publicly without evaluating any protected row. Endpoint classes
use one log-sigmoid component. Private guards and masking apply to all rows.

## Binding arithmetic amendment (2026-09-18)

1. Replace protected q64 nonlinear evaluation with a certified low-precision
   piecewise-polynomial log-sigmoid/softplus profile. Keep the frozen f50/f100
   input contract and round only after adding owner partial predictors.
2. Retain the analytic probability floor from the public maximum argument
   magnitude and minimum gap. Derive an approximation-aware cap separately;
   do not mislabel its exponential as the exact probability floor.
3. Bind the complete numeric profile, rounding and error budget in both server
   and client validators; stale or tampered numeric contracts fail closed.
4. Keep registration/release disabled until the fused producer provides
   authenticated shared sums and joint-DP evidence. No local plaintext fallback
   can satisfy that gate. The DSLite synthetic test is explicitly a test-tagged
   reference harness, not evidence of production PSI or MPC execution.
5. Record actual Boolean gate/traffic cost and treat the reviewer's cost target
   as an independent promotion gate. Public utility tests compare n times the
   certified error with the DP noise scale for their declared defaults.

## Implementation and review decisions

6. Keep the retained q64 exp/log helper exclusively for PUBLIC signed threshold
   gaps, then round that constant to q16. Protected rows use only the new
   low-precision profile. This avoids amplifying q16 exponential error near
   gap=1/16 while keeping Go and pure-R constants identical.
7. Select the public adjacent thresholds using the private outcome before
   evaluating at most two softplus components. This keeps nonlinear work
   bounded independently of the number of ordered classes.
8. Require the participating pair to equal the two compute/noise authorities;
   preserve the same guard in both validators. Existing same-owner routes
   remain unchanged.
9. Measured Boolean circuit cost exceeds the binding target. Registration and
   public release remain fail closed; source-only numeric correctness and a
   synthetic DSLite reference test do not authorize production promotion.


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
