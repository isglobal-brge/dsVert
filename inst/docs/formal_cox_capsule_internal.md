# Formal grid-Breslow Cox PH capsule: internal vertical slice

Status: **internal, sealed, `production_ready = FALSE`**.  No function in this
slice is registered as a DataSHIELD aggregate or assign method.  It does not
reuse the historical exact Cox implementation.

## Public lifecycle status (security-profile schema v4)

This note preserves component-level research evidence; it is not readiness
evidence for a public route. Schema v4 reports
`route_claims$formal_cox_ready = FALSE` with state
`sealed_no_recipient_encrypted_r_dsi_lifecycle_or_end_to_end_numeric_certificate`.
The top-level client `ready` value and the server compatibility alias
`formal_dp_claim_eligible` describe the biomedical joint-DP capsule route only;
neither promotes formal GLM or formal Cox.

Formal Cox remains sealed until recipient-encrypted source materialization,
the complete registered R/DSI schedule, the durable common finalizer and the
route-level end-to-end numeric/identifiability certificate are bound into one
tested release lifecycle. None of the internal Go/R harness evidence below
closes that lifecycle by itself.

## Audit of the historical route

The existing client profile route is correctly listed as `quarantine` in the
method inventory and is not a basis for this capsule.  Its source shows that:

- `n_obs`, `J`, `n_pp`, event-time dimensions and later `n_events` are returned
  outside a formal DP release;
- the client reconstructs an exact length-p score and p-by-p information
  matrix on every Newton iteration, plus score/step histories;
- its risk-floor branch emits data-dependent errors and its sparse-tail logic
  groups later event times into the final retained tick, which changes ties and
  therefore can change the partial-likelihood target;
- it uses Ring127 approximations for nonlinear operations and has no
  end-to-end no-wrap/error certificate for the complete Cox iteration;
- byte encryption and secret sharing protect transport/intermediates, but do
  not make repeated exact score/Hessian openings differentially private.

Those are useful prototype components, not a disclosure-safe production Cox
release under the current threat model.  The new slice does not call any of
those endpoints and does not expose a compatibility fallback.

## Scientific target

The v1 target is a bounded, optionally ridge-penalised Cox proportional-hazards
partial-likelihood coefficient on a **public fixed time grid**, with Breslow
handling of ties.  Its label is
`bounded-ridge-grid-breslow-cox-ph-partial-likelihood-v1`.

The grid is part of the estimand and must be fixed ex ante rather than derived
from observed patient event times.  An observation time must equal one signed
public tick; the materializer never snaps a protected time to the nearest tick.
If a custodian bins formerly continuous times before creating the immutable
snapshot, the induced ties change the partial likelihood and the result must
remain labelled grid-Breslow Cox PH.  It is not an approximation silently
relabelled as the Cox fit under the original event ordering.  A discrete-time
pooled-logistic hazard model is a different estimand and is not used here.

Supported in the internal reference:

- `Surv(stop, status)` and one counting-process interval
  `Surv(entry, stop, status)`, with risk interval `(entry, stop]`;
- one row and at most one event per patient;
- time-fixed numeric covariates;
- unit case weights;
- one baseline-hazard stratum;
- `ties = "breslow"`.

Case weights, multiple strata, recurrent events, time-varying covariates,
Efron/exact ties, baseline-hazard publication and classical or robust standard
errors are not supported by v1.  They must not be inferred from the legacy
surface.

## Signed, server-owned contract

The canonical schema fixes a non-patient-derived logical snapshot identifier,
complete peer pinset,
automatically selected two compute peers, owners of the response and every
covariate, patient capacity, grid, fixed-point precision, L2 bounds, beta ball,
ridge, iterations, step size, epsilon, delta, adjacency and minimum at-risk
count at an event tick.  Every pinned custodian must sign the same canonical
bytes with its Ed25519 identity key.  Validation rechecks all signatures and
the complete scientific contract before recomputing sensitivity.  A raw or
unkeyed patient-dependent snapshot hash is never placed in this schema.

Each source binds its actual immutable local snapshot privately.  A 32-byte
local binding enters a source-root HMAC and produces a different MAC for each
recipient.  These MACs are not public hashes, are not comparable across
sources, and are not used as a patient-alignment equality gate.  They are
integrity bindings inside the recipient-specific encrypted source envelope.

There is no sensitivity or bound parameter supplied by the analyst and no
accepted sensitivity override.  A schema missing a strictly positive at-risk
floor cannot be sealed or certified.  The at-risk floor is needed for the
future reciprocal/numerical-validity circuit and for a meaningful risk set; it
is not substituted into the privacy theorem to claim artificially smaller
noise.  Whether protected rows satisfy it must remain a secret GC validity
predicate, never an exact released count.

## Threat model and non-claims

The intended production protocol is a pinned, semi-honest two-compute-peer
MPC among a unanimously approving consortium of K custodians.  It requires at
least one of the two selected compute peers not to collude with the other peer,
the analyst or the analyst-controlled relay.  K may be 2, 3 or larger; all K
custodians sign the schema and contribute a fixed-shape source envelope, while
exactly two pinned peers hold complementary shares.  If those two peers
collude, they can reconstruct the shared lanes.  Secret sharing cannot prevent
that, and this slice does not claim malicious-secure MPC.

The relay may delay, drop, duplicate, replay, reorder or replace traffic.  It
must be unable to forge a custodian signature, authenticate a modified source
envelope or make peers accept different signed schemas; its remaining power is
denial of service.  The current R object has a source-local HMAC and both
**plaintext-hex** shares only as an executable fixture.  Its metadata says
`test_fixture_plaintext_not_transportable_v1`; it is neither encrypted nor a
transport envelope.  Tests assert that it has no namespace export, DSI method
registration or Go command.  Promotion
requires recipient-specific encryption/signatures and the real typed DSI
source channel so the relay never receives both plaintext share envelopes.
The internal R exact-GC transport now recognises the common Gaussian one-draw
worker only behind an authority gate.  That gate revalidates the signed
biomedical manifest and exactly two recipient tickets, binds their pinned
cryptographic IDs, the source fan-in transcript and the worker purpose, and
places only the resulting authority digest beside the staged local share.  It
adds no AggregateMethods entry and exposes no operation, backend, output kind,
seed, policy or share argument.  It is substrate for the missing Cox adapter,
not evidence that the formal Cox materializer has traversed DSI.

A malicious custodian can submit false local data, deliberately disclose its
own data or collude with both compute peers.  Peer pinning proves identity and
prevents silent peer substitution; it does not prove truthfulness of a
custodian's database.  Formal patient-level DP concerns the final analyst
release under the signed adjacency/domain.  It does not hide public schema
metadata (capacity, grid, owners, bounds) or make unlimited distinct adaptive
capsules free of privacy composition.

## Privacy calculation

For the normalized Cox score, capacity `N`, `||Z(t)||2 <= Cz` and an iterate
projected to `||beta||2 <= Cbeta`, Lemma 9 of Hung and Yu gives the replacement
sensitivity upper bound

```text
Delta2 = 4*Cz/N
       + exp(2*Cz*Cbeta) * (2*Cz + Cz^2) * log(N + 1) / N.
```

The lemma treats neighboring fixed-size datasets differing in one complete
`(T, Delta, Z(.))` triple.  dsVert's add/remove contract uses a public fixed
capacity: adding or removing one patient replaces one canonical zero-weight
slot, so it uses the same one-triple bound.  It is not multiplied by two.
Ridge contributes a deterministic data-independent gradient and does not
increase this sensitivity.

Lemma 9's `log(N+1)` step uses the ordinary Cox at-risk process.  With delayed
entry, risk sets can increase as patients enter and that harmonic argument no
longer applies unchanged.  The single-interval contract therefore uses the
more conservative universal bound `sum_g d_g/r_g <= N` (one event per patient),
giving

```text
Delta2_left_truncated = 4*Cz/N
                      + exp(2*Cz*Cbeta) * (2*Cz + Cz^2).
```

This extension can materially reduce utility, but it does not silently apply
an inapplicable theorem.  The signed at-risk floor is not used to shrink this
privacy bound.

## Fidelity and utility limits

The central oracle agreement tests establish fidelity to `coxph` for the
**signed grid-Breslow target**, before DP noise and when the bounded optimum is
interior.  They do not establish equality to a Cox fit on a finer continuous
event ordering, to Efron ties, or to an unbounded/unpenalised fit when the
schema selects a beta ball or positive ridge.  Hazard ratios `exp(beta)` are
safe post-processing of the eventual single coefficient release; standard
errors, p-values, confidence intervals and baseline survival are not supplied
by v1.

Utility is not unconditional.  The sensitivity grows exponentially in
`Cz*Cbeta`, and the delayed-entry extension can be substantially noisier than
the no-entry theorem.  Covariate scaling, coordinate bounds and the beta ball
must therefore be fixed from public scientific knowledge or a separate DP
procedure—not exact minima/maxima learned and released from the study rows.
The fixed iteration count and step/ridge settings also define the candidate
algorithm and require prospective simulation.  The internal Go slice has a
finite-support one-draw sampler, an exact integer-lattice Cox circuit and an
authoritative compiler from the unanimously signed R schema.  Release
calibration is recomputed from the implemented Go lattice policy; no
analyst-supplied sensitivity is accepted.  There is still no end-to-end
nonlinear/optimizer approximation-error certificate or real DSI execution, so
no empirical accuracy or coverage claim is made for a deployable DP output.

The candidate follows CDP-Cox Algorithm 3 from the same paper.  For `K`
interactive projected iterations, its internal Gaussian standard deviation is

```text
sigma = Delta2 * sqrt(K/epsilon *
        (2*log(1/delta)/epsilon + 1)).
```

The paper proves central `(epsilon, delta)`-DP for the output under its stated
bounded-covariate and projection contract, using Rényi-DP composition.
Distributional, Hessian-eigenvalue, censoring and tuning assumptions are also
needed for its statistical convergence/utility results; dsVert does not turn
those into unconditional finite-sample inference claims.

Primary references:

- Hung and Yu, [Optimal Cox regression under federated differential privacy:
  coefficients and cumulative hazards](https://arxiv.org/abs/2508.19640),
  especially Algorithm 3, Proposition 8 and Lemma 9 / Appendix D.1.
- The authors' primary [FDPCox reference implementation](https://github.com/EKHung/FDPCox),
  including `grad_sensitivity()` and `cdp_cox()`.
- Hung and Yu, [Differentially private hypothesis testing in survival
  analysis](https://arxiv.org/abs/2605.16906), which separately develops
  private Cox tests and explains why private Hessian-based inference is not a
  routine post-processing step.
- The official `survival` documentation for
  [`coxph`](https://stat.ethz.ch/R-manual/R-devel/library/survival/html/coxph.html)
  and its Breslow/counting-process semantics.

## Fixed-shape vertical materialization

For K=2, K=3, K=4 and K=5 custodians, every source emits the same schema-determined
Ring128 lane layout:

```text
[one hidden validity bit per source,
 entry index, stop index, status,
 one fixed-point lane per covariate] x public capacity.
```

Only the declared owner contributes a response/covariate lane.  Each source
contributes its own hidden validity bit.  A value `v` is split modulo `2^128`
as `(r, v-r)`, where `r` comes from a source-local 256-bit root through a
domain-separated HMAC bound to schema, logical snapshot, source-private
snapshot binding, recipient pair, slot, field and the private lane value.  The
value is only an input to the keyed PRF and is never emitted as a hash.  This
prevents exact share differencing if an operator mistakenly reuses a snapshot
binding after changing a row.  The fixture's two recipient shares
must be replaced by separate authenticated
typed-source envelopes.  Neither compute peer receives a plaintext lane.

The internal Go exact-GC circuit now ANDs source-validity lanes, checks the
fixed response/covariate domains and L2 bounds, evaluates fixed-work grid risk
sets and Breslow scores, applies exact signed fixed-point floors and projection,
and returns only fresh coefficient shares plus a sealed validity bit.  Its
finite-support sampler validity is consumed inside the same circuit.  The R
reconstruction helper still exists only for tests and is not remotely
reachable; the authoritative typed R-materializer-to-Go handoff is not wired.

The R fixture materialises both plaintext-hex recipient lists in memory and is not the
large-cohort transport implementation.  Production must stream the canonical
slot/field sequence independently to each recipient using bounded chunks,
absolute authenticated offsets, backpressure and idempotent retry.  Chunk
boundaries are transport-only: rechunking must reproduce the same coordinate
stream and final sticky release.  This is compatible with direct DSI calls and
does not require statistical query batching, but the real DSI/GC path remains
a promotion blocker.

The Go planner selects Ring128 or a dynamic power-of-two ring up to Ring4096
from public bounds.  A requirement above Ring4096 is a typed zero-opening error
rather than a wrap.  Ring128 source and sampler shares are high-limb checked,
then sign-lifted exactly into the selected dynamic ring.  The joint discrete
Gaussian has fixed finite support; its tail and dyadic-CDF total-variation
losses are explicitly charged to signed delta, and the circuit consumes one
sealed validity share per canonical sampler chunk. Within the unregistered Go
harness, the final RingK coefficient shares reduce exactly modulo `2^128`, are
shifted by the public beta bound and pass through the internal durable common
finalizer. Ring256 lifting and final-carrier reduction have explicit component
regressions; this is not an R/DSI route.

This closes silent modular wrap and the formerly missing sampler/finalizer
adapter only for the internal Go slice. Each admission now carries a hashed,
machine-checked component certificate for the selected ring, scale, maximum
signed magnitude, deterministic and finite-noise no-wrap bounds, Ring128
lifting/final reduction, outward exp-table error, exact signed floor/division
rules and equality to the independent big-integer lattice oracle.  The
certificate explicitly sets all continuous-trajectory, optimizer-distance,
convergence and end-to-end claims to false.  A single bound covering the
distance from this implemented fixed-iteration lattice trajectory to the
continuous Cox optimum is still pending.
`final_numeric_error_certificate` and production readiness therefore remain
false.

## Internal component evidence recorded

The focal test suite covers:

- unanimous K-peer signatures and signature/tamper rejection;
- absent/zero at-risk floor rejection;
- sensitivity recomputation and fixed-capacity adjacency semantics, plus an
  exhaustive finite-state replacement/add-remove audit of the implemented
  normalized score (a regression check, not a replacement for Lemma 9);
- the conservative delayed-entry sensitivity branch, Ring128/dynamic
  deterministic planning, and explicit absence of a full fixed-ring/noise
  certificate;
- central coefficient and log partial-likelihood agreement with
  `survival::coxph(ties = "breslow")`, including tied events;
- counting-process delayed entry agreement;
- K=2, K=3, K=4 and K=5 fixed-shape Ring128 share reconstruction;
- wrong-root, wrong logical snapshot, wrong private snapshot binding/replay,
  pin rotation, source/metadata tampering and modified-share rejection;
- value-bound PRF masks, deterministic same-snapshot restart and
  source-order-independent reconstruction;
- a fixed-work private reference that returns no score, Hessian, risk set,
  count or log-likelihood, performs zero openings and rejects numeric overflow
  with a typed zero-opening error;
- an exact generated Cox circuit against an independent big-integer lattice
  oracle, plus real authenticated two-peer Yao runs for K=2,3,4,5;
- the authoritative signed-R-schema-to-Go compiler for K=2,3,4,5, including
  unanimous signature verification, R-canonical label/integer bounds,
  recomputation of the exact-lattice privacy plan, and rejection of unknown,
  duplicate, tampered or unanimously re-signed values outside the R contract;
- finite-support Gaussian planning with tail/CDF transfer charged to delta,
  fixed shape and no-wrap bounds for K=2,3,4,5;
- real local sampler-Yao -> Cox-Yao -> purpose-bound signed provenance ->
  durable single common opening for K=2,3,4,5, with byte-identical restart;
- rejection of sampler/noise/output substitution, record tamper, replay and
  wrong-recipient traffic;
- a durable CAS regression that commits private validity-output receipts after
  the ledger barrier while preserving valid rechunk/reorder replay;
- verification of the two actual signed `open_authorized` control-plane tokens
  against the pinned compute pair, allocation, capsule/query/scope, release
  chain and sampler seed commitment; mismatched allocations, stale digests,
  forged signatures and seed substitution are rejected;
- recipient-local typed source fan-in receipts that bind all K source receipts,
  fixed coordinate shape, aggregate-share digest and recipient identity while
  serialising no aggregate share; and
- the R Gaussian one-draw authority gate described above, including rejection
  of missing/duplicate tickets, changed fan-in transcripts and changed
  purposes, plus a regression that no public DSI method can select this
  backend or output kind.

## Exact blockers to promotion

Promotion requires all of the following, not a documentation change:

1. Connect the source-private, recipient-specific materializer to the existing
   authenticated typed source fan-in and DSI path, using the now-enforced R
   manifest/ticket/purpose gate.  Neither the analyst relay nor one compute
   peer may receive both plaintext source-share bundles.
2. Complete the end-to-end nonlinear numeric/optimization certificate and add
   a DP-safe identification/convergence artifact.  Exact curvature, risk-set
   sizes, event counts, score, Hessian and log likelihood must remain closed.
3. Run the real multi-process server-spec -> materializer -> DSI -> sampler GC
   -> Cox GC -> durable common release path for K=2,3,4,5, including key/pin
   rotation, tampering, replay, crash, retry, transport reordering and
   representative large-cohort performance tests.

Until those blockers close, this slice establishes an executable statistical,
numeric and transport contract, not a production DP Cox method.  Different
logical capsules still compose in privacy; unlimited byte-identical replay and
post-processing of one sticky release do not make unlimited distinct adaptive
releases globally private.
