# Independent-full-draw joint-DP fallback

Status: integrated and tested as the scalable backend of the registered
biomedical-vector release. It deliberately has no standalone noise or payload
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
transcript, runs the existing adapted Google-DP/ChaCha20 sampler with the
complete global epsilon and the globally allocated delta (never epsilon/K),
and adds its raw signed noise to its share modulo 2^k. A joint finalizer sums
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
`delta_mechanism`, and their sum `delta_total`.

This is not malicious-secure. A deviating peer could add a data-dependent
value, bias the result or create another channel. The one-hidden-seed argument
does not cover that behavior. Timing claims also remain output-DP only;
sampler, cache, admission, transport, failure and availability timing are
outside the current guarantee.

The one-draw exact-GC route has lower variance, but the current public cost
policy promotes it only for a scalar Laplace vector. Wider Laplace vectors use
this convolution backend. That choice is made and signed before source shares
or seeds are read; a timeout or worker failure cannot switch the backend.

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
finite support can break a pure-DP boundary ratio. Both raw samplers return
signed int64 draws. For every coordinate the backend proves that

`[statistic_lower + 2*INT64_MIN,
  statistic_upper + 2*INT64_MAX]`

lies in the signed side of the declared ring. Ring arithmetic then carries the
complete raw domain with checked multiprecision addition and no wrap. Ring127
is rejected because it fails the 128-bit mask-entropy policy.

The pre-saturation value must never be delivered. The joint finalizer performs
one signed reconstruction and the committed saturation. Output bounds must lie
inside `[-(2^53-1), 2^53-1]` for exact JSON/R transport. Count should use the
direct `[0, unit_capacity]` saturation; it is DP-safe post-processing and avoids
negative or impossible released counts.

The granular-Laplace ideal has unbounded support, whereas the inherited raw
sampler is represented in `int64`. Consequently this fallback does **not**
claim pure DP. With sampler rate `lambda`, `M=INT64_MAX`, `K=2` peers and `d`
coordinates, the implementation uses the conservative coupling bound

`TV <= 2 * K * d * exp(-lambda * M)`

where the leading two covers the zero/sign rejection loop. It then charges

`delta_impl_sampler <= (1 + exp(epsilon)) * TV`.

The calculation uses outward-rounded floating-point operands/results and a
non-zero reported floor of `2^-100`. For Laplace, `delta_mechanism=0`; the
full implementation bound must fit the fixed capsule parameters before seed syntax
is accepted or any draw occurs. A zero-delta proposal is unavailable.

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
sequential scalar releases. Its finite-support implementation delta is still
union-bounded across both peers and all coordinates. For a Gaussian vector,
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

Go tests cover strict schemas, Ring127 and weak-entropy rejection, complete raw
headroom, exact reconstruction of `S+raw(N_A)+raw(N_B)`, Count-specific final
clamping, sticky Laplace/Gaussian replay, independent streams, likelihood
ratios at both clipping atoms, variance/RMSE multipliers, the mask-translation
bijection, all Ring128 split endpoints, reconstruction and entropy failures.

R tests cover source/mask/clipping bindings, durable allocation and seed
commitments, fixed capsule epsilon propagation, fail-closed metadata, Count
bounds, capsule retry reuse without reallocation, the server-local split
contract, encrypted peer transfer, final-only reconstruction, Merkle replay,
restart and compaction. Both suites also prove that zero or underfunded delta
fails before seed handling, that finite support cannot be advertised as
universally pure DP, and that the reported non-zero tail bound dominates the
two-peer vector union bound. External multi-host Opal/Armadillo validation is a
deployment test obligation; the package capability is no longer disabled or
provisional.
