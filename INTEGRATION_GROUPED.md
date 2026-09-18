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
1. Resolve the scalar profile cost and outward coefficient certificate gates.
   Complete GEE bread/meat error propagation; replace provisional R error=1.
   Make Go/R caps identical: GLMM currently supplies a universal local cap,
   R signs candidate-specific caps; GEE Go sums row-capped likelihood whereas
   R signs a cluster cap. The fused adapter MUST enforce the final signed
   cluster cap and map bread shifts/caps exactly before share accumulation.
2. Validate both owner signatures, policy, PSI source, complete predictor dot
   at f100, clipping/encoding, grouping ownership, one-row/patient rule,
   no-eviction capacities, stable original AR1 slot distances and private
   routing controls. Reject private grouping/validity failure for the release.
3. Bind private Beneš stage chunks, fixed padded cluster/candidate traversal,
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
6. Run real process-isolated DSLite source/PSI/noise/replay/crash tests and the
   n=10000,p=10,m=50 resource matrix. Current signed domains are smaller
   (C<=64, B<=16; GEE B<=8,p<=3,m<=32) and do NOT meet that envelope.

Test-only bridge: `go test -tags grouped_reference_test -c -o /tmp/grouped-reference.test .`.
Only the tagged `_test.go` contains the JSON fixture reader; production builds
cannot dispatch it. Environment paths are test inputs, never production knobs.
The DSLite test explicitly registers base::identity for public synthetic tables,
compares tagged integer grids with real finite-grid objectives and pooled
lmer/glmer/geeglm fits, and uses two conservative synthetic Laplace draws plus
client postprocessing at epsilon 1/4/8. It does NOT implement or claim the
missing production fused path, real PSI, sticky ledger or authenticated noise.
