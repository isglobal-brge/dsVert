# Grouped integration handoff — do not enable release

Bases: server primitive 38146c0, client cb26ecd. No shared producer files changed.

Entry points:
- Server `.dsvert_register_grouped_cross()` returns spec/contract/artifact/source
  builders and a fail-closed materializer (`production_enabled=FALSE`).
- Go `registerGroupedLMM()`, `registerGroupedGLMMLoss()`, `registerGroupedGEE()`
  return typed cluster compilers; no generic nonlinear RPC or CLI is registered.
- Client `.dsvert_dp_grouped_grid_cross_register()` supplies validators and
  postprocessing; public dp_lmm_grid/dp_glmm_grid/dp_gee_grid are exported.
  The reader always fails closed.

Required wiring, in order:
1. Scalar <=5000-AND and outward coefficient gates now PASS (4f2d314).
   The old composed-GC traffic blocker is withdrawn under clause 5.
   Scalar-only compact chunks now pass with private guards/masks; see
   BENCH_GROUPED_CLAUSE5.md. Complete exact two-authority share arithmetic
   using the interface obligations in CLAUSE5_ARITHMETIC_GROUPED.md.
   Do not conflate a scalar gate pass with full-release admission.
   Complete GEE bread/meat error propagation; replace provisional R error=1.
   Make Go/R caps identical: GLMM currently supplies a universal local cap,
   R signs candidate-specific caps; GEE Go sums row-capped likelihood whereas
   R signs a cluster cap. The fused adapter MUST enforce the final signed
   cluster cap and map bread shifts/caps exactly before share accumulation.
2. Validate both owner signatures, policy, PSI source, complete predictor dot
   at f100, clipping/encoding, grouping ownership, one-row/patient rule,
   no-eviction capacities, stable original AR1 slot distances and private
   routing controls. Reject private grouping/validity failure for the release.
3. Apply private Beneš routing ONCE to packed feature/outcome/validity rows;
   never repeat it per candidate. Bind its stage chunks and subsequent traversal,
   fresh output masks, previous-state shares and no replay/duplicate/skipped
   chunk to the signed semantic identity and exact generated-source digest.
   Compile/preflight every public shape before protected source resolution.
4. Feed typed kernel outputs into exact shared sums; consume private validity
   only in the authenticated release gate. Apply signed full-vector L1/L2
   calibration, joint two-authority noise and sticky semantic release. Do not
   expose cluster count, losses, scores, validity, quadrature terms or shares.
5. Supply authenticated output evidence/state
   `cross_owner_exact_gc_materialized` / `exact_gc_to_joint_dp_vector_v1`,
   then implement the client reader. Contract state strings alone are not
   evidence. Keep generation-one and same-owner dispatch untouched.
6. Run real process-isolated DSLite source/PSI/noise/replay/crash tests and
   measured n in {2000,4000,10000}, grid in {16,32,50}, Q=5 for GLMM.
   Admit only a measured <=60 GB / <=2 h envelope under clauses 4/5. Current signed domains are smaller
   (C<=64, B<=16; GEE B<=8,p<=3,m<=32) and do NOT meet that envelope.

Test-only bridge: `go test -tags grouped_reference_test -c -o /tmp/grouped-reference.test .`.
Only the tagged `_test.go` contains the JSON fixture reader; production builds
cannot dispatch it. Environment paths are test inputs, never production knobs.
The DSLite test explicitly registers base::identity for public synthetic tables,
compares tagged integer grids with real finite-grid objectives and pooled
lmer/glmer/geeglm fits, and uses two conservative synthetic Laplace draws plus
client postprocessing at epsilon 1/4/8. It does NOT implement or claim the
missing production fused path, real PSI, sticky ledger or authenticated noise.


Revised profile: `grouped-pwlinear-q16-k64-range-exp-v2`; both R validators
bind the new manifest hash. Re-sign manifests; never retain signatures over
the old arithmetic. All six public coefficient tables now have rational
interval certificates. Public test bridge also supplies profile-boundary
fixtures, exclusively under `grouped_reference_test`.

No shared Step-2 release wiring has landed in this lane. The materializer and
client reader still reject every protected invocation. No callback injection,
synthetic evaluator, environment flag or artifact state bypass is provided.

Clause-5 additions (a5c7dc2): internal groupedScalarCompile,
groupedShareBlockSums, groupedCompactRunGarbler/Evaluator. Existing family
registrations still return legacy cluster prototypes; do not dispatch them
as the new share-composed producer. New scalar chunks retain q16 profile
semantics and include private validity. They do not perform Ring128/f100
conversion, secure products, private masking, signed caps or release fusion.
No new production operation is registered. Compact engine import is exactly
Step-2 0006f1a for the two engine files; legacy entry points remain unchanged.
Client registry now explicitly quarantines the three exported prototypes.

## Addendum 3: owned exact arithmetic now implemented

`registerGroupedExactArithmetic()` is the shared component consumed by Step 2.
Inputs are one authority's existing Ring192 operand shares, a fresh existing
`exactGCSession`, role, and `groupedArithmeticPlan{Contract,Previous,Chunk,Count}`.
Count is public and in 1..1024. Contract is the signed schedule digest; Previous
is the COMMON authenticated predecessor receipt digest (not either authority's
local receipt MAC); first chunk is zero/zero. A fresh SessionID is mandatory on
every attempt, including retries, as for the existing record engine. The caller
must validate source purposes and persist/consume schedule state atomically.

The protocol generates local random triple shares, two checked-OT cross terms,
opens only masked Beaver differences over authenticated records, and returns
local Ring192 product shares plus a domain/role/share-bound local HMAC receipt.
No dealer or approximate truncation is used. Security remains the engine's
semi-honest two-authority model with checked OT; no malicious arithmetic proof
is asserted. The local MAC is NOT a release attestation or durable ledger.
Both peer receipts must be included in the authenticated common continuation.

Pod component result: 1024 products, 37,912,128 measured two-direction bytes,
7.903936 seconds in the final run; source hash and tests are in
inst/grouped-validation/dealer-free-product.json. This does not admit any of
the nine release envelopes. LMM sufficient-statistic components and exact
f264 output boundary are in INTEGRATION_LMM.md. GEE/GH5 share composition,
full measurements and Step-2 fusion remain unfinished. Old ownership/traffic
blocker conclusions are withdrawn; no new full-release traffic failure is claimed.
