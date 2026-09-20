# Remaining Cox release integration

The server workload artifact loop now validates the signed Cox schema/contract via
`.dsvert_dp_glm_grid_profile_admit` and projects the Cox artifact into the existing
raw/natural L1/L2 accumulator. Real manifest -> source-contract -> Cox source
context is verified at K2/K3/K5 without schema/catalog/transport doubles.
The source producer, native kernels, staged executor and arithmetic are unchanged.

The public release is still disabled. Finish these coordinated boundaries before
claiming fleet readiness:

1. Publication and certificate: `dp_synopsis_vector_runner.R` must collect Cox
   publication evidence both after fresh execution and on durable cold replay.
   Reuse `.dsvert_dp_cox_cross_public_evidence_set` with the authenticated policy
   projection (pins, designated authorities, capacity, grid bits, adjacency) and
   signed schema. On cold replay rebuild compilation only; never re-read Claims.
   `ds.vertDP.R` must retain the evidence in the result context.
2. `dp_gaussian_certificate.R`: accept the Cox descriptor only with required
   signed Cox evidence; include and reconstruct that evidence on offline/cold
   verification. Preserve common-lattice coordinate bounds and dispatch Cox's
   finite-grid moment, not a GLM moment. Wire the still-rejecting
   `.dsvert_dp_cox_grid_cross_release` into the authenticated Synopsis flow.
3. Coordinate runtime states in server `crossgrid_cox.R` and client
   `dp_cox_grid_cross.R`. Server generic grid discovery still omits Cox. When
   adding it, explicitly exclude Cox from the legacy GLM result injection loop:
   `.dsvert_dp_glm_grid_cross_inject` filters only staged grouped artifacts,
   whose predicate currently excludes Cox. Cox already has separate injection
   and private-validity/sampler handling; never inject twice. Keep the existing
   dedicated Cox layout/Claim/producer paths; time values never become a GLM
   outcome block. Add regression coverage for mixed-family rejection.
4. Extend `validate_structured_dslite.R` for pinned time/event-owner garbler,
   <=400 scoped fixture, actual native recovery, cold reader and tamper checks.
   Use an independent integer oracle. Keep all GEE branches untouched.
5. Fresh signed small source -> native -> joint-DP proof first, then four Cox
   release-manifest jobs and fleet first run. No heavy-wave duplicate runs.

The present contract's runtime_enabled remains false; metadata admission is
not a real release, capacity proof, or promotion. N<=400 remains enforced.
The shared optional-Gaussian handling remains integration-owned and unchanged.
No sampler patch is needed by the GEE lane.
