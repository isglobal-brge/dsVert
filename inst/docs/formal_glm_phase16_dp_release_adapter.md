# Formal GLM Phase 1.5/1.6: sealed coefficients and one-draw DP adapter

Status: internal and deliberately unregistered. These phases add no R export,
AggregateMethod, worker command, packaged binary, or general runtime capability.
`ProductionReady` remains false and no opening is currently authorized.

## Public lifecycle status (security-profile schema v5)

This note preserves component-level research evidence; it is not readiness
evidence for a new public computation route. Schema v5 reports
`route_claims$formal_glm_ready = FALSE` with state
`sealed_no_registered_r_dsi_joint_dp_release_lifecycle`. The top-level client
`ready` value and the server compatibility alias `formal_dp_claim_eligible`
describe the biomedical joint-DP capsule route only; neither promotes formal
GLM or formal Cox. It separately reports the read-only completed-certificate
route; this component cannot create such a certificate.

Formal GLM remains sealed until the protected materializer, the complete
registered R/DSI schedule, the durable common finalizer and the route-level
end-to-end numeric certificate are bound into one tested release lifecycle.
The adapter and certificate results below are internal component evidence only.

## Implemented path

Phase 1.5 streams the fixed-schedule GLM computation through exact two-party
garbled circuits and retains only additive coefficient shares. Its release
bridge reconstructs a coefficient only inside the circuit, clips it to the
cross-signed box `[-B_j,B_j]`, applies signed-floor quantization, translates it
to a non-negative Ring128 coordinate, and emits fresh additive shares:

`floor(beta_j / d) + ceil(B_j / d)`.

Here `d` is the public power-of-two downsampling denominator. The bridge never
opens `beta`. The R postprocessor consumes only the already-DP, exactly-once
common opening and returns exact signed rationals (integer numerators with one
power-of-two denominator). It does not convert through an R double. A value
outside the certified range is rejected, not silently clamped a second time.

Phase 1.6 now compiles the common exact-GC two-peer
`joint_discrete_gaussian_one_global_draw` worker with allocation
`one_stacked_capsule_vector`. Each designated compute peer derives private
fixed-width random input from its sticky seed; the circuit XOR-combines both
streams, samples one public dyadic-CDF Gaussian vector, validates the Ring128
source, performs the saturating clamp, and returns fresh payload shares plus
validity shares. A relay receives no seed, random stream, source share,
pre-noise coefficient, or validity bit.

The finite-support tail and outward dyadic-CDF approximation are charged once
to the implementation delta. The plan publishes exact rational privacy and
total-variation certificates, a simultaneous 95% absolute-error radius, and a
conservative circuit cost projection. There is no automatic substitution by a
Laplace or two-independent-draw mechanism.

## Machine-proven integer L2 sensitivity

Two positive integer bounds are recomputed from the cross-signed fixed-point
policy; the smaller is selected:

- the universal translated-box diameter
  `ceil(sqrt(sum_j (2*ceil(B_j/d))^2))`;
- an exact fixed-point coordinate recurrence covering the configured
  add/remove or replace-one row adjacency, link-table slopes and span, weights,
  residuals, capacity averaging, ridge step, every optimizer iteration, and
  projection to the coefficient box.

The recurrence first proves source-coordinate bounds `a_j`. Downsampling then
uses the coordinatewise integer fact

`abs(floor(x/d)-floor(y/d)) <= ceil(abs(x-y)/d)`

and finally computes
`ceil(sqrt(sum_j ceil(a_j/d)^2))`. Applying one scalar ceiling only after an
L2 division is unsound: with `p=2`, `d=10`, simultaneous source differences
of one can cross both signed-floor bins, producing quantized differences
`(1,1)` and integer L2 bound two. Exhaustive small-domain tests cover this
case and enumerate adjacent fixed-point GLM inputs for both adjacency models.

The complete certificate commits to every recurrence step, candidate bound,
selection rule, policy, plan, theorem, ranges, lattice, and adjacency. Its
domain-separated SHA-256 digest is included in the canonical Phase-1.6 release
preimage. The common worker reparses that preimage and recomputes its digest;
it also checks epsilon, delta, Ring/lattice, dimensions, bounds, K, pinset,
roles, commitment contexts, seed commitments, and release/transcript hashes.
It does not, by itself, derive the recurrence from the policy. Phase 1.7 is the
authoritative gate that rebuilds the bridge and certificate from the approved
plan and compares their canonical bytes before accepting this worker.

Every translated coordinate and the selected L2 bound must fit signed
Ring128. Otherwise compilation returns a typed numeric error. Noise addition
uses a saturating in-circuit clamp, so modular wrap is never returned as a
valid release.

## Binding, peers, and threat model

The public release binding covers capsule, manifest, schema, workload,
source-context, release instance and release contract; the Phase-1.5 plan,
bridge, final receipt pair, checkpoint and accumulated fan-in transcript;
snapshot, full consortium pinset, family, link table, kernel, bounds,
adjacency, quantizer, coefficient order, DP parameters, complete sensitivity
certificate, roles, commitments, ranges, and the one-opening contract.

Exactly two pinned compute peers run Yao/OT. Their roles are selected by
lexicographically sorting the cryptographic `dsv1_` identities derived from
pinned Ed25519 keys, never by response order or analyst-controlled aliases.
All K custodians remain bound into the complete pinset and fan-in transcript;
K=2, K=3, and K=5 are tested. A manipulating relay can delay, drop, duplicate,
or reorder traffic, but cannot silently change a bound computation or release
without causing verification failure. It can still deny service.

The cryptographic claim is limited to the pinned, semi-honest,
non-colluding two-compute-peer model with at least one honest compute peer.
Collusion of both compute peers can reconstruct additive shares. These phases
do not establish malicious-secure Yao/OT or protect against a deliberately
incorrect input jointly endorsed by every responsible custodian.

## Ring63 and multiprecision coverage

The bridge input container is
`max(exactGCTypeBits(sourceRing), 128)` and its public input budget is
`3 * containerWidth * p`. Ring128 output masks therefore cannot overlap source
fields for Ring63. Actual-circuit tests cover Ring63, Ring127, and a source ring
above 128 bits, including output-mask bits above bit 64.

This is evidence for the specific Phase-1.5 bridge and Phase-1.6 worker path.
It does not promote a general `exact_gc` or multiprecision end-to-end runtime
capability, and it does not change a public `numericPolicy` flag.

## Cost, utility, and scalability

Phase 1.5 bounds per-circuit working memory and automatically reduces only the
physical row block until that public envelope fits. It does not drop rows,
iterations, methods, or requests. This prevents a single circuit from growing
with all N rows, but the present schedule performs one exact-GC block for every
block and iteration. With at most four coefficients and
`block_capacity * p <= 4`, its communication and OT/compiler work are roughly
linear in `N * iterations`; for `p=4` the block contains one row. Consequently
the current kernel is memory-bounded but is not a credible large-N or p>4
scalability solution.

The one-draw Gaussian worker is independent of N after coefficients are
formed, but its public-CDF lookup has `M-1` Boolean comparisons per coordinate,
not free logarithmic RAM access. It chunks coordinates under explicit gate,
non-XOR, garbled-table, wire-label, compiler-memory, and typed-input envelopes.
Those are per-circuit safety limits, not request-count or privacy-budget gates.
The cost projection is checked against the compiled circuit before private
input is read.

Utility is therefore controlled transparently by the selected sensitivity,
epsilon/delta, coefficient lattice, box clipping, fixed-point approximation,
and the published simultaneous-error certificate. The recurrence can reduce
noise substantially relative to the universal box bound, but no claim of
centralized-model numerical equivalence or large-dataset speed is made here.

## Current public-route blockers

Phase 1.7 now authenticates a canonical formal-GLM manifest projection, a
K-of-K signed source-contribution statement, every semantic hash, and a K-of-K
signature over the final worker-bound admission preimage. This closes
caller-supplied certificate and unsigned-binding admission, but it does not
inspect protected rows.

At the time of this phase, authorization returned the historical typed blocker
`formal_glm_protected_materializer_and_dsi_opening_unavailable` with
`openings_performed = 0`. Later internal phases added a protected materializer,
a durable local finalizer and Phase-1.9 fan-in/release components. Internal
Phase21 now derives the exact source share and its binding directly from the
authenticated Phase20 handoff for both selected DP backends. The one-draw
path consumes the hidden execution-validity share inside its bound predicate;
the independent-full path binds both the exact pre-noise range guard and the
signed noised peer share to the same durable source. Both persist a false
predicate as a terminal no-release and bind cleanup to the certified two-peer
release. This closes that component-level substitution gap but does not
retroactively promote the adapter. It is not joined by a registered R
endpoint and complete DSI coordinator, checkpoint-root rotation continuity,
deployment timing and scalability evidence, or a
route-level end-to-end numeric certificate.

The current public frontdoor therefore remains sealed with
`formal_glm_phase19_durable_r_dsi_release_bridge_not_promoted`. No signed
component claim is presented as protected-data E2E or route-readiness evidence.
