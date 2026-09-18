# Signed cross-owner binomial and Poisson grids

Custodians can authorize `binomial_grid_cross_v1` and `poisson_grid_cross_v1`
with the certified piecewise profile `cross-grid-certified-piecewise-k64-v2`.
Every participating custodian signs the same ordered candidate coefficients,
bounds, family, profile/certificate hashes, source encoding and alignment
contract. The outcome custodian publishes the complete contract as the
`contract` JSON scalar in its `gaussian_specs` fragment. All peers verify it
against the unanimously signed schema before materialisation.

The client call is `ds.vertGLM(..., family = "binomial" or "poisson",
analysis_id = "<signed analysis>")`. A vertically partitioned formula uses
qualified references, for example `site_a$y ~ site_a$x1 + site_b$x2`.
The formula must match the signed candidate design. There is no analyst-chosen
optimizer, candidate mutation, clipping bound, privacy parameter or noise seed.

## Computation and release

The existing pinned PSI route establishes a common private row alignment.
Custodians clip finite records to signed bounds, form the bounded patient mean,
and encode normalized predictors at f50. Outcomes must be bounded integers
(binomial 0/1; Poisson 0 through the signed maximum). Invalid/missing inputs
exclude that patient's entire candidate-loss contribution. Validities and
alignment checks remain private. A grid-only source stream first passes the
bilateral all-owner digest gate. Only then may the typed producer read the
authenticated source shares; its fused circuit repeats the alignment guard for
every row. Mixed-family streams retain the full private-coordinate mask path.

The two computation authorities sum partial linear predictors exactly on the
f100 lattice and evaluate the certified profile in Boolean MPC. Binomial uses
a 64-piece softplus profile; Poisson reduces the exponent by ln(2), evaluates
a small-interval profile and applies the certified shift. The coefficient L1
envelope is one of 1, 2, 4, 8, 16. Source/coefficients remain f50 and the signed
loss lattice remains g=8 through 18. The analytic approximation/rounding error
is included in the per-patient caps and therefore in joint sensitivity.
The common smallest enclosing envelope may conservatively increase noise for
candidates with smaller individual bounds.

A fixed traversal uses at most 32 rows and eight candidates per kernel batch.
Only additive candidate-sum shares enter the globally calibrated
two-authority exact-GC joint DP sampler. The grid-specific cost policy admits
at most 51 public coordinates (50 candidates plus the canonical count for a
count-plus-grid catalog); the older families retain their one-coordinate
exact-noise admission policy. Covariate references do not implicitly request
additional numeric moments. Noise chunks retain the global privacy calibration. This route currently
admits the certified discrete-Laplace mechanism; a catalog selecting another
mechanism fails closed instead of using an older convolution release. Private MAC-authenticated batch/final records
bind the signed source contract and permit retry. Injection adds the final
share to the original aggregate once; repeated reads do not accumulate it.
The sticky key binds the signed grids, family/version, mechanism including
privacy parameters, caps, and the authenticated source/alignment claim binding.
Changing these creates a different release; retrying them does not create a
new independent draw.

## States and interpretation

For these two admitted cross-owner families the public states are
`implementation_state = "cross_owner_exact_gc_materialized"` and
`cross_owner_state = "exact_gc_to_joint_dp_vector_v1"`. Admission fails closed
when signatures, profile hashes, bounds, source geometry or alignment bindings
are missing or inconsistent. The older signed q64 reference contract does not
authorize the new profile. Other reserved families are not promoted by this
route.

DP-best selection takes the smallest **released DP** candidate loss; ties use
the first candidate in signed order. Coefficients are transformed from the
signed normalized design back to the public original scale. This is selection
from a finite grid, not a continuous MLE. There are no standard errors,
covariance estimates, p-values, residuals or fitted values. Approximation error
and DP noise can change the selected candidate. Public catalog/signature and
formula validation precede protected source claims; fetching a previously
unknown public catalog necessarily precedes validation against that catalog.

The release has a transport-anchored certificate containing only public
metadata and DP coordinates. Exact losses and noise seeds are available only
to the source-tree synthetic validation harness, never through DataSHIELD.
