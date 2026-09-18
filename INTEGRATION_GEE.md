# GEE composition integration — incomplete predecessor

`registerGroupedGEE()` now exposes MomentOperands, MomentSums, MomentBoundary,
MeatOperands and MeatFinal; LegacyCompile is only the preceding monolithic
prototype. The new components accept receipt-bound whitened `(u,z)` row factors
at q64, form exact f128 private products through the dealer-free OT component,
reduce locally, clip/round cluster scores, and form exact clipped-score meat.
Bread and meat use the signed column-major upper triangle, caps and shifts.
Private validity accompanies every boundary output.

The tested components do NOT create the private whitening factors. Their tests
exercise supplied synthetic factors and all three correlation-dependent output
mappings, NOT end-to-end exchangeable/AR1 generation. This mandatory predecessor
is still owned by this lane:
- privately validated feature/outcome/complete-case inputs and scalar profile
  factors, using the new guarded predictor and Ring192 scalar bridge;
- inverse working-correlation construction with secret live count, and stable
  original-slot gaps for AR1 after missingness; no public count or unsafe
  full-block inverse with zeroed rows;
- a measured efficient factor/product schedule, with grouping ONCE per release;
- complete propagated likelihood/bread/meat error certificate and matching R
  integer oracle/profile binding. The existing provisional GEE error=1 is NOT
  certified by these component tests and MUST NOT authorize promotion.

After those prerequisites: map the signed per-cluster likelihood cap rather
than summing only prototype row caps, connect authenticated Step-2 fusion,
run protected DSLite/geepack comparisons, measure all nine full envelopes and
admit only a measured capacity. R production dispatch remains disabled.

For exact q64 factor inputs, products/sums have zero arithmetic error while
inside the certified signed Ring192 range. Bread's final rounding adds <=1/(2S).
Clipped-score rounding to q16 adds <=2^-17 per component; because both exact
and rounded scores stay in [-C,C], the meat perturbation is <=C/65536 plus
final <=1/(2S). These conditional bounds exclude unfinished upstream factor
errors. They are not a full-family certificate.
