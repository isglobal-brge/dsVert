# NB2 cross-owner integration

This extension is isolated from the sealed and same-owner routes. Its registered
objects describe `nb_grid_cross_v1`, artifact
`bounded-negative-binomial-cross-likelihood-grid-v1`, implementation state
`cross_owner_exact_gc_materialized`, and cross-owner state
`exact_gc_to_joint_dp_vector_v1`. The state strings alone are not result evidence.
The new client entry fails closed until an authenticated release adapter is wired.

## Single registration seam

Call namespace-internal `.dsvert_dp_nb_grid_cross_register()` in each R package.
The returned descriptor contains `build_spec`, `validate_spec`, `build_artifact`,
`validate_artifact`, `build_source_contract`, `validate_contract`, and `sensitivity`.
The client additionally supplies `client_entry` (`dp_nb_grid`) and `postprocess`
(`.dsvert_dp_nb_grid_cross_moment`). `production_release_registered` remains FALSE.

Raw specifications use the frozen GLM contract's fields plus `theta_grid`.
`beta_grid[[j]]` and `theta_grid[[j]]` describe one paired candidate. Candidates
must already be ordered by canonical JSON of `list(beta=beta,theta=theta)`;
there is no implicit Cartesian product, permutation, or signed coefficient
reassociation. Both exact duplicate candidates and f50 encoding collisions at the
same theta are rejected. Identical beta vectors at distinct theta are supported.
Theta must be exactly one of `2^(-3:7)`. Other positive real theta values are
outside this certificate and fail before source access.

The shared schema and complete contract require every pinned peer's real
Ed25519 signature, including both custodians. Existing dataset qualification,
predictor order, signed bounds, pinned PSI metadata, source-only ownership,
complete-case masks, exactly two compute/noise peers and frozen Ring128 layout
remain authoritative. This family session validates the two-custodian topology;
additional source-owner topologies are preserved by the contract but require
separate producer/release campaigns before promotion. NB uses predictors followed by one integer outcome block;
it adds no clear per-patient constants or losses to the transcript. The public
numeric profile contains all candidate-theta/outcome constants; the circuit
selects the constant using the private outcome.

## Wiring still required in the Step 2 integration worktree

1. Add this descriptor to the shared family registry through its single
   registration function; connect the NB Go registration from the circuit file.
   Do not dispatch the plaintext reference evaluator in a production build.
2. Resolve the authenticated source contract through the fused producer, preserve
   the original f100 dot-product sum across both owners, run the registered NB
   row kernel, gate every row by private alignment and validity, and reduce only
   candidate sum shares. Enforce public resource limits before resolving inputs.
3. Bind theta order, NB profile/certificate hashes, source layout, candidate
   identities, batching and result-share evidence into the fused transcript.
   Inject candidate shares only after both result attestations have been checked;
   missing/partial results must never become zeros.
4. Register workload/source/release dispatch for the new versions, using the
   complete candidate-vector `U_j`, Delta1 and Delta2 already present in the
   signed specification. Preserve both joint noise authorities, epsilon/delta,
   source claims, replay identity and sticky semantic publication ledger.
5. Replace the final fail-closed branch of `dp_nb_grid` with the authenticated
   cross-grid release adapter. It must validate the released vector's evidence
   against this signed contract before calling `postprocess`. Do not add an
   arbitrary caller-supplied evaluator/release callback. The additive
   `export(dp_nb_grid)` registration already exposes the fail-closed entry.
6. Extend typed-method inventories, transport/certificate dispatch and release
   evidence checks only after the real producer is connected. Run interrupted
   and replayed two-peer releases, source cleanup, source-only-owner layouts,
   malformed evidence/signatures, and measured GC resource gates. The tagged
   DSLite reference harness is arithmetic/integration test evidence only; it
   does not certify a production two-party release.

## Synthetic test helpers

`tests/testthat/helper-nb-grid-cross.R` defines
`.nb_grid_cross_fixture(package, capacity, bits, beta_grid, theta_grid, max_outcome)`
with two genuine signing identities. It returns signed contract, policy, schema,
authenticated schema, raw spec, signing closure, and registration descriptor.
This helper accepts `package="dsVert"` or `"dsVertClient"` and never obtains
protected data. Its example predictors are `peer_a$x`, `peer_b$z`, with outcome
`peer_a$y`.

`helper-nb-grid-integer.R` is a pure-R base-2^15 limb oracle using the frozen
`helper-cross-grid-integer.R` arithmetic. `.cross_nb_reference_row` consumes
synthetic q64 eta fixtures; `.cross_nb_reference_batch` forms the complete shared
linear predictor before rounding. Both remain test helpers, outside package R
production dispatch. The profile JSON's boundary/slack, saturation, invalid-row
and theta-extreme fixtures are consumed unchanged by Go and R.

## Day 1 arithmetic retarget (2026-09-18)

The source f50/f100 ABI and q64 complete-eta interface remain frozen. Replace
all earlier Chebyshev references with the pinned q16/w32/K64 quadratic softplus
profile from `inst/cross-grid-nb/numeric_profile_nb_v1.json`. Both Go and R use
identical symmetry, piece selection, Horner rounding, tail, constants and final
clamp. `NUMERIC_CERTIFICATE_NB.md` supplies the analytic error and width extension.
The new candidate bounds contain `certified_row_error` and `endpoint_error` and
include approximation slack; old signed NB contracts must be rejected.

The producer should reuse the registered softplus profile for shifted NB input,
then assemble outcome-owner constants and the linear terms in shares. A private
outcome is not a public coefficient: no adapter may disclose it to the other
custodian or analyst under the label “cleartext-by-share.” Preserve the frozen
source representation, or separately version and sign any added constant-share
blocks. The self-contained full-row Boolean kernel remains available to verify
exact loss assembly but its measured cost does not establish envelope feasibility.

Do not promote until the selected engine satisfies the measured per-evaluation
cost target and resource admission before input access. Preserve the full-row
private domain bit in the producer terminal guard; do not turn malformed inputs
into an apparently valid zero loss. Bind the profile identity, certificate and
candidate-specific error/caps into both result attestations and sticky identity.

For utility, compare against the same clamped exact loss and allow
`N*(E_j+1/(2S))` per candidate. The family regression checks the stated default
workload N=10000,p=10,m=50,M=16,theta=2,A approximately16 at epsilon 1,4,8 and
requires that bound below 1% of the Laplace whole-vector noise scale. This is a
specific workload check, not a guarantee for every allowed capacity/grid.
