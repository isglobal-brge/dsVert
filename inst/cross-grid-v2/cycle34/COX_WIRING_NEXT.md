# Remaining public Cox lifecycle hooks (read-only map)

The new client reader is `.dsvert_dp_cox_cross_read_vector` in
`dsVertClient/R/dp_cox_grid_cross_release.R`. Its trusted bundle/compilation
inputs are prerequisites, not caller-overridable proofs. Keep its real
RELEASE/REPLAY/publication checks when connecting the production reader.

1. Server/client discovery: `dpGLMGridCrossMaterializer.R` /
   `dp_glm_grid_cross_materializer.R` currently exclude Cox. Do not merely add
   Cox to the grouped predicate: grouped orchestration dereferences `grouping`
   and uses grouped operation names. Cox has an explicit time-owner route and
   `cox-loss-staged-v1` operation. Reuse its validated source-context/layout,
   producer, committed-source, prepare and bind adapters.
2. Schema retention: `dpSynopsisLifecycleDS.R` currently retains `signed_schema`
   only when `.dsvert_dp_lmm_cross_artifacts(manifest)` is nonempty. A Cox cold
   bind/reader will need the same authenticated schema source, gated by exact
   Cox admission. Reuse `dpLMMSignedSchema.R` rather than accepting caller data.
3. Remote bind: `.dsvert_dp_lmm_cross_remote_bind` is grouping-specific. Cox
   needs source transport-gate validation, owner snapshot revalidation and
   authenticated routing-receipt delivery before `.dsvert_dp_cox_cross_bind`.
   Preserve the existing admission request/artifact/source checks before
   staged prepare/start/store/finalize dispatch; do not bypass them.
4. Before DP START: `dpSynopsisExecutionDS.R` currently calls only
   `.dsvert_dp_lmm_cross_sampler_binding`. Cox has its own public terminal
   adapter `.dsvert_dp_cox_cross_sampler_binding`; use authenticated schema and
   source context, without private candidate reads before START.
5. After DP START: `dpCapsuleSourceTransportDS.R` currently invokes only the
   existing GLM/Gaussian/categorical/LMM injectors. Route Cox to
   `.dsvert_dp_cox_cross_inject` after the existing complete-source checks,
   preserving raw Ring128 shares, validity, public stage identity and caps.
6. Client runner and portable certificate: `dp_synopsis_vector_runner.R` and
   `dp_gaussian_certificate.R` currently discover grouped artifacts and
   verify `cross_lmm_evidence_json`. Cox needs explicit typed admission and
   certificate wiring. Its new internal reader covers signature/hash/lattice
   composition only; it cannot make an unvalidated compilation trustworthy.

Proof must then join actual committed producer/sharing -> native worker ->
durable result -> DP sampler -> authenticated cold reader on fresh small
snapshots before marking any manifest row ready. Current staged scope N<=400;
do not borrow the larger kernel-only capacity measurements. Native replay,
public bilateral/unilateral recovery, cold/tamper and measured capacity remain
separate gates. Do not edit the GEE lane or restart any frozen heavy job.
