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
