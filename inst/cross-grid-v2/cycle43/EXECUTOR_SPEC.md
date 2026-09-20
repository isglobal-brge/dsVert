# Staged authenticated durable executor — DESIGN DECISIONS (reviewer spec for the 6 heavy families)
# Resolves STRUCTURED_EXECUTOR_SPEC_REQUIRED.md. Families: LMM, GLMM binomial, GLMM Poisson,
# GEE binomial, GEE Poisson, Cox. No new math: the kernels (GEE whitening v3, GH5, Cox Ring64->128
# bridge, exact OT Beaver products) are DONE and must be retained. This is the release-lifecycle
# protocol that composes them durably. Implement on branch feature/cross-owner-grids.

## A. Architecture: a STAGE GRAPH, not a single batch pass
Replace the single-stage assumption in dpGLMGridCrossLifecycle.R with an ordered list of typed
STAGES per family. The executor runs stages in order; each stage consumes predecessor receipts and
produces an authenticated durable record. A family = {signed schema, ordered stage list, final ABI}.

## B. Per-stage ABI (resolves req 3). Every stage record carries EXACTLY:
- `ring` in {128,192}; `fp_scale` (q-bits, fixed per stage); `coord_order` (canonical, documented).
- `public_bounds` (admitted domain used); `validity` = 1 bit/coordinate, AND-composed from ALL input
  validities (source + profile + product); a coordinate invalid anywhere stays invalid to the end.
- `source_digest`, `profile_digest` (pin the exact signed inputs); `predecessor_receipts[]` (hashes).
- `share_mac` per authority: a MAC over that authority's masked share under a domain-separated key
  keyed by (session, stage_id, attempt_nonce). `output_mask_domain_tag` (domain-separated re-mask).
- Content address: `stage_receipt = H(public_plan || stage_id || predecessor_receipts || source/profile
  digests || committed masked-share commitments)`. Two authorities must agree on it before COMMIT.

## C. Ring128 -> Ring192 conversion (resolves req 3; CORRECTED cycle6 — my original masked-lift was
NOT exact under wraparound, e.g. x=1, r=M-1 gave 1-M. astra's derived correction is APPROVED.)
Let M=2^128. Products of two q-scaled Ring128 values overflow 128 bits, so product operands are
extended to Ring192 BEFORE a Ring192 Beaver multiply. Never locally zero-extend additive shares.
EXACT conversion of an additive Ring128 sharing [x] (x = x_1 + x_2 mod M) to Ring192:
- Draw the mask r as a dual-ring edaBit-style correlated value from preprocessing: r in [0,M) shared
  BOTH mod M ([r]_128) AND in Ring192 ([r]_192) reconstructing to the SAME integer r, so lift(r) is
  exact by construction (do NOT re-lift Ring128 shares of r).
- Open z = (x + r) mod M. z is a one-time pad (r uniform in [0,M)) so opening it leaks nothing about x.
- Set the Ring192 shares by the CORRECTED identity:
      [x]_192 = lift_public(z) - [r]_192 + [z < r]*M - [x >= M/2]*M
  (omit the final sign term for unsigned inputs). BOTH comparison bits are PRIVATE shared bits computed
  inside the boundary and NEVER opened: [z < r] compares public z against shared r; [x >= M/2] is the
  two's-complement sign bit. Result = true signed integer x, exact on wrapped and signed boundaries.
- Then Beaver-multiply in Ring192. This conversion is a stage with its own MAC + receipt. Tests:
  TestCrossGridStageConversionMaskedOpeningNeedsPrivateCarry (the defect) and
  TestCrossGridStageConversionPrivateCarryIdentity (the corrected identity) both PASS on pod4.

## D. Durable commit + recovery (resolves req 4 — THE crux). Two-phase per stage:
- PREPARE: each authority computes its output share using attempt-scoped OT nonces, persists
  {masked share, attempt_nonce, predecessor_receipts, stage_receipt} + a PREPARE marker.
- COMMIT: authorities exchange PREPARE stage_receipts; iff equal and matching the public plan, each
  writes a COMMIT marker. Output is then "mutually committed."
- Recovery:
  * both COMMIT present -> REPLAY: reload committed shares, continue. Deterministic.
  * one COMMIT, one only PREPARE -> the PREPARE side re-writes COMMIT from its PERSISTED share
    (idempotent; shares/nonces are on disk, not regenerated). Reconcile by stage_receipt equality.
  * no COMMIT (crash at/before PREPARE) -> ABORT the attempt: discard BOTH sides' PREPARE shares and
    attempt nonces; start a FRESH attempt with NEW OT streams + NEW nonces. NEVER mix old+new shares
    or reuse OT/record nonces.
- CORRECTNESS INVARIANT (state this in the thesis + a test): the final opened artifact =
  f(true sufficient statistics, sticky semantic seed). The true sufficient statistics are a fixed
  function of the private inputs, independent of attempt/nonce/recovery path; the noise is sticky
  (seed-derived), drawn ONCE (resolves req 5). Therefore replay and fresh-attempt yield the SAME
  final bytes -> DSLITE_ORACLE_BITWISE_EQUAL holds on every recovery path. Execution retries/receipt
  changes MUST NOT trigger a new noise draw.

## E. Source materialization (resolves req 3, the LMM point)
dpGLMGridCrossMaterializer.R gains an `outcome_encoding` per family: {integer} for count/binary,
{fixed_point:q} for LMM fractional outcomes and any fractional design column. Emit Ring128 additive
shares at the family q-scale. Group/time columns are materialized as PRIVATE routing inputs, never
opened.

## F. Routing once, private membership (resolves req 2)
One oblivious permutation (existing primitive) per release packs rows into cluster order (grouped) or
risk-set order (Cox), padded to public bounds. Cluster labels, order, live counts, event times and
tie masks stay private; padding + within-cluster slot gaps are bound through every downstream stage's
validity. Public topology (padded sizes) is fixed and identical across candidates.

## G. Fixtures + admitted domains (resolves req 6)
- GEE/grouped fixture: place roles on SEPARATE owners so K5 gives all five a source role — owner A =
  cluster/time labels; owner B = outcome; owners C..E = covariate blocks. K2/K3 collapse blocks but
  keep group and outcome on different owners. GEE p<=3 stays; do NOT put outcome+group on one owner.
- Raise the admitted cluster-count domain from C<=64 to the largest C that fits the 256GB/8h gate at
  n2000 (the 500-cluster harness = ~4/cluster is realistic GEE); MEASURE it, record per family.

## H. Per-family stage graphs (build + validate IN THIS ORDER; one real n2000 release each before next)
1. LMM: materialize(frac) -> route -> OT products {X'X, X'y, y'y per cluster} (Ring192 via C) ->
   candidate-independent sufficient-stat assembly -> REML/ML grid loss (certified) -> select -> DP.
2. GLMM binomial: as LMM + GH5 quadrature nodes (certified profiles) over the random-effect variance
   grid; per-cluster GH composition.
3. GLMM Poisson: as GLMM binomial with range-reduced exp; factorial EXCLUDED from selection (constant).
4. GEE binomial: route -> OT products -> moment-estimate alpha ONCE (candidate-independent) -> public
   whitening coeffs (bounded-denominator admitted domain on alpha) x private products (v3 producer) ->
   bread + clipped-meat -> grid loss -> select -> DP.
5. GEE Poisson: as GEE binomial, Poisson mean/variance; no GLM substitution.
6. Cox: route to risk-set order -> Breslow partial-likelihood profiles -> Cox Ring64->128 bridge
   invoked PRIVATELY (req 5) -> grid loss -> select -> DP.

## I. Promotion gates (capacity revised by David 2026-09-20, req 7): real two-authority n2000 bitwise oracle equality; bilateral
AND unilateral recovery; cold replay; swapped/tampered source+stage rejection; full paired suite;
capacity measured vs the uniform 256GB/8h ceiling (no censored/extrapolated runs). Mark Promoted=Yes
only then.

## J. Execution
astra ULTRA. pod4 build/prove host. Build the shared staged executor first, then wire families in the
order above, proving one real n2000 release per family before moving on. Checkpoint (commit + STATUS)
at token budget; this will take multiple cycles. Retain all completed arithmetic. No tags, no thesis
edits, no origin pushes. If a SPECIFIC arithmetic/certificate sub-point is genuinely impossible (not
just laborious), write BLOCKED_<family>_<piece>.md naming it precisely and continue with the others.
