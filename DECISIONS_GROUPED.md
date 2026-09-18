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

- Shared index-bit conditions cut scalar AND counts from 8623–10084 to
  4027–5488 without changing profile arithmetic. Narrowing lookup value words
  passed scalar fixtures but changed composed binomial GEE bread by several
  integer ulps. Reverted narrowing; retained 32-bit lookup words. Expanded
  compiled profile tests to 385 inputs per function (2695 total).
- Rechecked upstream Step 2 at c10bc0d: it also explicitly fails the required
  cost gate (2773–4019 ANDs/evaluation) and leaves production disabled.
  Therefore no compliant approved shared emitter is available to substitute.
  Do not bypass the arithmetic memo or raise limits to force integration.

### Resumed 2026-09-18 — revised gate

The reviewer's GATE_REVISION_2026-09-18.md overrides the former scalar and
traffic budgets. Do not stop against the old threshold or interpret the new
scalar threshold as a whole-release measurement. Preserve runner caps and
production rejection until authenticated wiring and numeric gates pass.
Range reduction must cover both Poisson exponentials and quadrature exp.

- Replaced lookup mux trees with shared Boolean bit-plane decision diagrams.
  Full int32 values are reconstructed explicitly; this avoids the earlier
  unsafe narrow-word optimization. Scalar and composed integer equality pass.
- Replaced both exp tables with one [-1/2,1/2] table, q16 ln2 reduction and
  fixed five-stage barrel shifts. MPCL rejects variable shift expressions;
  fixed stages implement the required secret exponent without changing caps.
  The profile now costs 4321 ANDs, below the revised 5000 ceiling.
- Extended the exact-rational coefficient checker to all six tables (390
  knots). GLMM error propagation now counts both eta and node half-ulps.
  No epsilon, delta, signed coordinate cap or admission domain was weakened.
- Whole-release traffic is a separate gate. Pod probes count writes on BOTH
  encrypted transport endpoints. A chunk's exact garbled table payload times
  the public number of chunks is a mandatory lower bound, not a measurement
  of the full release. Never label extrapolated wire counts as observed totals.

## Resumed 2026-09-18 — clause 5 audit

Clean worktrees at resume. Fetched Step 2 through 8b6c7bf. The old
per-cluster traffic finding is superseded and cannot set the new capacity.
Import the explicitly requested compact framing from 0006f1a; move exact
linear operations to local shares. Audit secret products, live-count
reciprocals and private boundaries separately; none is a local linear map.
Inherited full Go and R checks still have no terminal result on the pod.

- Imported only the two compact engine files from the explicitly requested
  Step-2 0006f1a. Grouped runners additionally domain-separate record keys by
  framing mode, not only the GC digest. Legacy runner behavior stays intact.
- Private scalar-domain guards and masks stay inside each scalar chunk; batch
  validity stays secret. Use scalar temporaries before array writes to avoid
  the compiler's array-wide conditional multiplexers. At count=32 this brings
  exp to 4454 AND/value without changing coefficients or rounding.
- Exact block sums are local only after private routing and masking into
  public padded blocks. Secret squares/products, truncation/ring conversion,
  live-count coefficients and private segment boundaries are NOT local sums.
  The existing dealer/approximate-truncation helpers are not admissible under
  the current contract. Arithmetic-backend ownership/interface was raised for
  clarification; do not silently reinterpret the scalar-only restriction.
- Client package check exposed this lane's missing export inventory entries.
  Added one registration line to each shared R registry, with implementation
  in a new grouped file. Adjusted existing inventory/maturity test expectations
  for the three quarantine entries; old methods remain promoted as before.
  Explicitly assert no invented legacy remote-call evidence for new prototypes.

## Resumed 2026-09-18 — Addendum 3 arithmetic ownership

Both repositories are clean. The reviewer assigns dealer-free checked-OT exact
arithmetic to this lane; the prior ownership dependency is resolved. Implement
wide-ring Beaver products first, then candidate-independent LMM statistics,
GEE and GH5 composition. Do not reuse Ring127 truncation or widen shares by
zero extension. Full-release capacities still require full measurements.
Inherited pod checks still have no exit files; R_STACK_DONE reconfirmed.

- Addendum 3 exact products use fresh independent local a/b triple shares and
  two KOS-checked OT cross terms in Ring192. Beaver d/e openings are encrypted;
  no output rescale or dealer route is reused. Receipts bind context, local
  role and local output shares; persistence/consumption belongs to Step 2.
- LMM source f50 moments become f164 after q64 precision coefficients; frozen
  f50 beta-pair products require f264 accumulation. A single Ring192 cannot
  hold that exact integer. Use a carry/sign GC representation boundary into
  TWO Ring192 limbs, then public multiplication/addition locally in Ring384.
  This keeps source/transport ABI and runner caps intact, avoids unapproved
  coefficient quantization and needs no intermediate arithmetic rescale.
- The sufficient-statistic LMM equation has different rounding placement from
  the old per-row q64 prototype. Give it a new signed profile identity on both
  R sides, an independent residual oracle and pure-R limb oracle. Retain the
  former prototype only under the explicit LegacyCompile registration field.
  The 1e-8 pre-output error bound still encloses the new equation analytically.
