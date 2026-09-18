# Grouped lane decisions

## Resumed 2026-09-18

1. Preserve recovered work and audit it; no claim that the interrupted session
   completed validation. Binding arithmetic memo supersedes high-precision
   nonlinear circuit plans. Primitive routing/reductions and ABI stay unchanged.
2. One patient with exactly one analysis row is the DP unit. One admission or
   removal affects one cluster; replacement/movement affects at most two.
   Range-clamped cluster coordinates imply Delta1=a*sum(U),
   Delta2=a*sqrt(sum(U^2)), a=1/2 for admission/replacement respectively.
   Public capacity overflow is outside the signed domain, never handled by
   eviction. Private validity must gate the entire release, not drop bad rows.
3. Random-intercept variance and LMM residual variance are fixed across beta
   candidates. GH5 targets the signed finite quadrature, not adaptive GLMM fits.
4. Chunk-first geometry: private Beneš routing stages precede fixed padded
   cluster/candidate kernels, fresh output masks for each chunk, private validity
   carried to final authenticated release, exact shared coordinate accumulation.
   No counts or partial losses opened. Runner caps remain 32M gates/2 MiB source/
   512 Ki input bits. The integration adapter must bind each stage and chunk to
   the signed schedule and reject missing/duplicate/foreign chunks.
5. Existing recovered implementation narrows domains (GLMM eta<=1, GH5 variance
   0/.25; GEE eta<=4, p<=3). These are restricted prototypes, not the requested
   n=10000,p=10,m=50 resource gate. Keep production disabled until all relevant
   certificates, contracts and authenticated producer wiring agree.
6. GEE uses the user-mandated same-owner likelihood+bread+clipped cluster-score
   meat workload. The design's alternative global score norm is not substituted.

### Resumed audit outcomes

- All scalar profiles use piecewise q16 integer interpolation, no exact
  transcendental emitters. JSON coefficients are hash-bound in Go and R.
- Fixed equal-width wideMul operands, runtime q64 reciprocal casting and
  non-constant int192 count initialization for pinned MPCL behavior. Kept the
  primitive untouched. Replaced GEE's constant power-of-two division with
  explicit ties-even shifts (about 6.2M -> 1.7M gates in the three-slot probe).
- Public GEE score clipping now requires quarter increments on both R sides,
  matching Go; no clipping bound relaxed. Corrected log(3!) q16 from 117425 to
  117423 in GLMM and R. Invalid GEE oracle inputs now zero every coordinate.
- Tagged Go test executable is the only fixture-file evaluation entry. Synthetic
  DSLite uses explicit base::identity registration only in tests. Its two
  independent full-scale Laplace draws are conservative simulation, not a
  substitute for authenticated joint noise. Pooled fits are comparison targets,
  not computations permitted on protected data.
- Preserve unpromoted R error metadata for inspection, but explicitly prohibit
  using provisional GEE error=1 as a certificate. Full producer enabling is
  blocked by numeric/resource gates and unwired authenticated release stages.
