# Ordinal integration contract

New family entry points are `exactGCRegisterOrdinalLossV1()` in Go and
`.dsvert_dp_ordinal_grid_cross_register()` in each R package. The public client
is `dp_ordinal_grid()`. Existing `ds.vertOrdinal()` and its same-owner internal
grid implementation are untouched. Registration keeps `release_enabled=FALSE`.

Version is `ordinal_grid_cross_v1`, operation `dp.ordinal-grid-cross.v1`, profile
`cross-grid-ordinal-piecewise-q16-v1`. Required artifact states remain
`cross_owner_exact_gc_materialized` and `exact_gc_to_joint_dp_vector_v1`.
Reconstruct and validate signed profile/certificate/cap metadata; state strings
are not evidence of secure execution.

Remaining wiring follows `INTEGRATION_MULTINOMIAL.md` steps 1, 2 and 5..8,
with these ordinal-specific requirements:

1. Outcome integers follow the signed ordered levels. Private missing/ambiguous
   categories are invalid. No protected fitting/threshold estimation is allowed.
2. The sole eta uses zero intercept, public slopes with L1<=8 and magnitude<=8.
   Signed threshold magnitudes are <=8, adjacent gaps >=1/16 in both the raw
   binary64 and encoded f50 domains. K=2 uses one threshold and no gap test.
3. Construct `exactGCFamilyLossSpec{Classes, GridBits, Cap, Thresholds}` where
   thresholds are canonical signed-decimal f50 integers in signed class order.
   `registration.Source` validates them and derives only PUBLIC gap constants.
   This host calculation must never receive a protected row or predictor.
4. The Ring192 circuit garbler input has five coordinates: additive f100 eta,
   additive outcome, additive complete-case/alignment bit, loss mask, guard mask.
   The evaluator has the first three share coordinates. Output shares have the
   same `[loss-mask, guard XOR mask]` meaning as multinomial. Add eta shares
   before its sole q16 rounding. Threshold encoding and profile rounding must
   match the certificate exactly.
5. Enforce private guards, accumulate masked candidate sums, authenticate result
   evidence, inject shares once and invoke the joint-DP vector release. Never
   interpret a probability floor or valid numeric spec as permission to release.
6. Wire the client release seam only after that lifecycle is available. Client
   postprocessing returns the selected public coefficient/threshold candidate,
   transformed to original feature units, with no standard errors.

The stable loss uses log-sigmoid/softplus components and a public gap correction;
it never subtracts rounded private sigmoids. Its finite-probability domain and
uniform profile error are in `NUMERIC_CERTIFICATE_ORDINAL.md`. The tagged Go
reference and R oracle are test-only. DSLite comparison to `MASS::polr` is a
public-synthetic reference test; real PSI/MPC/noise execution remains an
integration gate. Cost and validation evidence are in `STATUS_ORDINAL.md`.
