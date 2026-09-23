# Independent-full-draw joint-DP fallback

Status: the dsVert 1.4.0 scalable Laplace fallback uses the exact v4 sampler;
the Gaussian route retains its positive-delta mechanism. The backend is
integrated into the registered signed release lifecycle. It deliberately has no standalone noise or payload
endpoint: capability is available only through the server-authoritative vector
manifest, allocation, source, sampling, finalization and replay lifecycle. The
older generic helper remains unregistered compatibility code and is not a
second release route.

## Capsule scope

This backend is a capsule-materialization primitive, not a per-analysis noise
API. Its source, seed commitment, masked shares and output certificate are
bound to one lowercase 64-hex `capsule_release_id`, canonically derived from
the consortium, logical snapshot/version, schema/adapter version, public
admission contract and privacy epoch. The source contract then commits that
identifier. A requested statistical method is intentionally absent from that
identity.

The capsule is allocated and sampled once. Retries reuse the same durable
allocation and sticky shares. Any number of supported methods may subsequently
operate only as post-processing of that fixed capsule: they neither allocate
epsilon/delta nor obtain a fresh draw. A new snapshot, schema or privacy epoch
creates a different capsule and is a separately accounted release.

## Protocol and privacy scope

Exactly two custodian-designated, identity-pinned peers hold uniformly masked
additive statistic shares in Ring2^k. Each peer derives a sticky seed from its
independent persistent noise root and the committed query/allocation/mechanism
transcript and samples with the complete global epsilon (never epsilon/K).
For the exact Laplace v4 fallback, each peer independently draws an unbounded
arbitrary-precision integer vector and adds its residues to its share modulo
`2^128`. The Gaussian route keeps its own certified positive-delta sampler. A joint finalizer sums
exactly those two shares,
signed-decodes once, applies exactly one public source-bound saturation, and
reveals only the saturated release.

Under pinned, semi-honest, non-colluding execution, both peers follow the
protocol and both noise contributions are independent of the protected data
and each other. If one peer's seed remains hidden, its complete mechanism is
`(epsilon, delta_total)`-DP. Adding the other independent draw and applying the
one fixed saturation are post-processing, so the single convolution release
keeps that same epsilon rather than doubling it. The certificate requires
`delta_total <= capsule_delta` and separately reports `delta_impl_sampler`,
`delta_mechanism`, and their sum `delta_total`. The exact v4 Laplace plan has
zero mechanism and implementation delta under ideal independent bits and
emits `guarantee = "pure-dp-under-ideal-bits"` and
`randomness = "keyed-stream-computational"`. Its replayable HKDF/ChaCha20 stream
needs the computational pseudorandomness assumption; this is not an
unconditional statistical claim about the finite seed space.

This is not malicious-secure. A deviating peer could add a data-dependent
value, bias the result or create another channel. The one-hidden-seed argument
does not cover that behavior. Timing claims also remain output-DP only;
sampler, cache, admission, transport, failure and availability timing are
outside the current guarantee.

The retained finite one-draw exact-GC route and its positive-delta certificate
remain separate from this v4 fallback. The backend choice is made and signed
before source shares or seeds are read; a timeout or worker failure cannot
switch the backend. Zero-delta acceptance is scoped to the exact v4 fallback.

## Uniform-mask contract

For every coordinate,

`share_A = r`, `share_B = statistic - r mod 2^k`,

where `r` is uniform over the complete ring, independent of the statistic,
fresh for every coordinate/snapshot/purpose and never reused. The productive
vector contract uses Ring128 and declares 128 bits of conditional min-entropy.
Translation by a fixed local noise is a permutation of Ring2^k, so a noised
share preserves that conditional uniformity exactly.

The Ring128 Count splitter consumes exactly 16 operating-system CSPRNG bytes.
No reduction is needed, so all 2^128 masks are equiprobable. It emits canonical
decimal residues and marks them `requires_durable_replay=true`; a producer must
persist the split before transport and reuse it after retries. The splitter is
server-local and is not a remote endpoint.

Masking cannot hide a statistic that a peer already materialized. Producer
attestation must therefore cover how the additive source was formed, not just
assert that a later random split occurred.

## Numeric and support contract

Component noise is never clipped locally. In particular,
`clip(S + clip(N))` is not substituted for `clip(S + N)`, because shifted
finite support can break a pure-DP boundary ratio. The v4 exact fallback
uses arbitrary-precision draws, modular Ring128 addition, one fixed signed
decoding and one public clamp. Ring127 is rejected by its Ring128 contract.
Planning requires `0 < epsilon <= 10000`, positive integer lattice sensitivity
`S`, `epsilon/S >= 2^-100`, and `1 <= d <= 1000000`.

The pre-saturation value must never be delivered. Output bounds must lie
inside `[-(2^53-1), 2^53-1]` for exact JSON/R transport. Count uses its fixed
`[0, unit_capacity]` saturation; it is DP-safe post-processing and avoids
negative or impossible released counts.

The exact fallback does not certify deterministic absence of wrap. Write
`q=exp(-epsilon/S)` and `B=2^127`. The positive outward decimal
`representability_bound` and `wrap_bound` bound `min(1,2*d*q^B)` for the event
`at_least_one_peer_draw_outside_signed_Ring128`; `wrap_bound_certified = true`
certifies that explicit event. Share/finalizer metadata separately bounds
full-sum wrapping with `sum_wrap_threshold = floor((B-M)/2)` and
`sum_wrap_bound >= min(1,2*d*q^sum_wrap_threshold)`, where `M` is the largest
public upper bound on the nonnegative scaled statistic. Threshold zero has
bound one. These are ideal-bit utility bounds distinct from mechanism delta.
The finalizer declares
`canonical_Ring128_twos_complement_after_modular_addition`, never
`after_proven_no_wrap`, for v4. Every unbounded integer has a ring residue;
there is no release failure or redraw on wrap.

Retained v3 finite Laplace artifacts keep their original finite-support
implementation delta and deterministic headroom checks. They cannot be read
as exact v4 artifacts. Gaussian finite-noise headroom is likewise unchanged.
See [the exact sampler specification](joint_dp_exact_laplace_ideal_bits.md)
for identifiers, proof, replay bit order and certified-bound construction.

For Gaussian, the signed biomedical manifest contains the exact fixed-work
dyadic-CDF plan, including the mechanism and implementation-error allowance.
The plan is eligible only when its total certified delta fits `capsule_delta`
and its certified simultaneous radius improves the admissible alternative.
The privacy argument selects the one hidden complete-capsule mechanism; the
other compliant, data-independent draw is post-processing, so peer deltas are
combined by the certified maximum rather than sequentially summed.

## Accuracy and accounting

Two equal independent draws have twice the nominal variance and sqrt(2) times
the nominal RMSE of the one-draw exact-GC route. The backend reports both
multipliers. Its 95% marginal and simultaneous radii use a conservative
two-component union bound, assigning half of the failure probability to each
component and also dividing simultaneous failure across coordinates.

For a Laplace vector, every coordinate uses the complete epsilon and the same
producer-proved global L1 sensitivity. This is one vector mechanism, not `d`
sequential scalar releases. Its v4 exact implementation delta is zero under
ideal bits; positive representability and sum-wrap utility bounds cover both
peers and all coordinates. For a Gaussian vector,
each peer uses the complete epsilon/delta and one global L2 sensitivity; the
signed fixed-work dyadic plan accounts for its mechanism and implementation
error before any seed is handled.

## Sticky and durable bindings

The vector wrapper consumes the two signed allocation openings and prepare
receipts, then reloads its durable capsule record. It verifies manifest,
release instance, allocation, mechanism, source/clipping contract, complete
pinset, designated identity, seed commitment and privacy parameters before
deriving the local seed. The same release instance after restart therefore
emits the identical local noised share without a new allocation. Distinct
peers use independent roots and peer-bound HMAC contexts.

Neither seed nor raw noise is returned. Only signed public contract metadata
and a purpose-bound ciphertext of the uniformly masked noised share leave the
local command. The vector lifecycle durably commits both local result roots,
consumes the two encrypted shares, reconstructs only the final noised/clamped
vector, signs its Merkle root and replays final public DP chunks byte-for-byte.

## Verification

Targeted Go and R tests cover production selection, zero-delta exact-fallback
admission, out-of-range refusal, certificate fields, modular reduction and
signed decoding, fixed clamping, and byte-identical replay. Exact-core tests
also pin stream/noise vectors and exercise arbitrary-precision draws and epoch
rollover. Legacy v3 and Gaussian tests retain positive-delta and finite-noise
headroom checks. The statistical battery calls the production sampler and has
a separate explicit ideal-reference flag.

External multi-host validation and the full grid and K=2/3/5 evaluation
batteries remain release validation obligations; targeted checks do not replace
those evaluations.
