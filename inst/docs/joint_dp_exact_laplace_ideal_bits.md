# Exact discrete-Laplace sampler core

Status: selected by the dsVert 1.4.0 v4 discrete-Laplace fallback for both
independent noise peers. Each arbitrary-precision draw is committed modulo
`2^128`; signed decoding and the fixed public clamp are post-processing.
Existing v3 artifacts retain their original finite-sampler guarantee.

## Exactness and randomness

`k2_joint_dp_exact_laplace.go` implements rational Bernoulli-exponential trials
and geometric sampling with `math/big`, following the construction in
[Canonne, Kamath and Steinke, Section 5](https://arxiv.org/html/2004.00010#S5).
For rate `alpha=epsilon/S`, the difference of two independent geometric draws
has mass `(1-q)/(1+q)*q^abs(z)`, where `q=exp(-alpha)`. Neither probabilities
nor outputs have finite cutoffs. With ideal independent bits, translating a
vector by this noise yields likelihood ratio at most
`exp(alpha*L1_distance) <= exp(epsilon)`. An independent second full peer draw
is postprocessing, including conditional on either peer's contribution.

That theorem requires ideal independent uniform bits. Replay uses a 256-bit
seed, HKDF-SHA256 and ChaCha20, so deployment additionally requires the keyed
stream pseudorandomness assumption. The production exact-mechanism metadata is
`guarantee="pure-dp-under-ideal-bits"` and
`randomness="keyed-stream-computational"`; it is not an unconditional
statistical claim about a finite seed space. No fresh random tape is stored.
Sampling time, memory access and availability are outside this output-DP
statement. The local rejection sampler is variable time.

## Replay specification

For epoch `e=0,1,...`, encoded in canonical decimal without leading zeros:

```
salt = transcript_hash decoded as 32 bytes
info = UTF8("dsVert/joint-dp/vector-convolution-private-stream/v4/")
       || contract_digest[32] || UTF8("/" + decimal(e))
key_nonce = HKDF-SHA256(seed[32], salt, info)[0:44]
epoch_bytes = ChaCha20(key_nonce[0:32], key_nonce[32:44])[0:65536]
```

The epoch is an arbitrary-precision integer; no epoch wraps. Bits are read
most-significant-first within each byte, continuously across draws and epochs.
Uniform `[0,n)` rejection reads `bit_length(n-1)` bits as a big-endian integer
and retries if it is at least `n`; `n=1` consumes no bits. CKS trials use exact
uniform comparisons. For each coordinate the first geometric is drawn fully,
then the second, and their difference is returned as an arbitrary-precision
integer. There is no retry limit or fallback distribution.

The tests pin a stream SHA-256 across two epoch transitions and twenty noise
integers at `alpha=7/256`. These vectors were generated with this implementation
on 2026-09-23 from the three SHA-256 string inputs in
`jointDPExactTestStream`. Run `go test -run '^TestJointDPExact' -count=1` from
`inst/dsvert-mpc` to check them. Finite-tape Bernoulli enumeration and empirical
PMF tests check the implementation; the algebra supplies the exactness proof.

## Admission, modular release and utility bounds

Planning enforces `0 < epsilon <= 10000`, positive integer lattice sensitivity
`S`, `epsilon/S >= 2^-100`, `1 <= d <= 1000000`, and ring width `W = 128`
before a seed is read. Both peer draws are unbounded integers. Each is reduced
modulo `2^128` when added to its share; the finalizer signed-decodes the modular
sum and applies the existing fixed public clamp. There is no magnitude cap,
wrap rejection or retry with fresh noise. This deterministic post-processing
preserves ideal-bit pure DP, including conditional on either peer's draw.
Consequently the exact fallback accepts `delta = 0`; Gaussian and finite v3
mechanisms retain their declared positive delta.

Staged grouped/LMM/GLMM/GEE/Cox source protocols that require the retained
finite exact-GC private-validity release still require positive delta. Their
zero-delta requests fail during planning; this fallback does not replace that
source-validity protocol.

For signed width `W`, `B=2^(W-1)`, and range `[-B,B-1]`, a draw is outside
the range with probability exactly `q^B`. Across two peers and `d` coordinates,
the union bound is `min(1,2*d*exp(-alpha*B))`. It is positive, even if a
floating-point evaluation underflows. The decimal-bound helper rounds outward
using `exp(3)>10` and retains arbitrary-precision scientific decimal exponents.
For the admitted ranges at `W=128`, its bound is at most `1e-44739235`, below
`2^-256`. The certificate stores this in `representability_bound` and
`wrap_bound`, with `wrap_bound_certified = true` and the explicit
`wrap_bound_event = "at_least_one_peer_draw_outside_signed_Ring128"`.

Individual representability does not establish headroom for the complete sum.
Let `M` be the largest public upper bound on the nonnegative scaled statistic
and `T=floor((2^127-M)/2)`. If each peer draw lies in `[-T,T-1]`, the complete
sum fits signed Ring128. Share and finalizer metadata therefore also stores
`sum_wrap_threshold = T` and `sum_wrap_bound`, a positive outward decimal bound
on `min(1,2*d*q^T)`, using the complete plan dimension `d`. A chunk uses its
own largest source bound to compute `T`; the maximum sum-wrap bound across all
chunks bounds wrapping anywhere in the full vector. At `T=0` the bound is one.
These probabilities describe
the ideal-bit distribution; deployed replay uses the cryptographic assumption
stated above. Neither utility bound is charged to mechanism delta, and neither
is a deterministic no-wrap assertion.

The plan, share and finalizer bind `noise_support = "unbounded_integer"` and
`noise_commitment = "modulo_2^128"`. The finalizer uses
`signed_decode = "canonical_Ring128_twos_complement_after_modular_addition"`.
It never emits the former `after_proven_no_wrap` claim for a v4 exact release.

## Production identifiers and compatibility

| Artifact | Identifier |
|---|---|
| Plan | `dsvert-joint-dp-vector-independent-full-draw-convolution-plan-v4` |
| Sampler | `hkdf-sha256-chacha20-independent-full-draw-exact-geometric-v4` |
| Backend | `independent_full_global_draw_convolution_ring128_v4` |
| Peer input | `dsvert-joint-dp-vector-independent-full-draw-convolution-input-v4` |
| Peer share | `dsvert-joint-dp-vector-independent-full-draw-convolution-share-v4` |
| Finalizer input | `dsvert-joint-dp-vector-independent-full-draw-finalizer-input-v4` |
| Finalizer output | `dsvert-joint-dp-vector-independent-full-draw-finalizer-v4` |

Readers distinguish v3 and v4. A v3 finite plan retains its positive
implementation delta, finite maximum draw, original stream and deterministic
headroom contract; reading it never upgrades its guarantee. New v4 plans bind
the exact support, admission range, randomness and utility metadata into their
release and sampler contracts. The v4 stream changes replay values relative to
v3; replay within one committed v4 release remains byte-identical. Upgrade
with release traffic paused and pending v3 workflows completed. Completed
stored v3 reads, replay and retained acknowledgements are supported; unfinished
v3 START/RESULT workflows and a first source-only acknowledgement without a
retained record are not migrated across the changed default planning policy.

## Synthetic production oracle

`joint-dp-vector-convolution-oracle-v1` is a local evaluation command, not a
registered DataSHIELD endpoint. It accepts explicit public test seeds, calls
the currently active production convolution sampler, and returns its actual
plan, metadata, peer draws and complete synthetic share inputs. It reads no
deployment noise root. Zero replicates performs a plan-only preflight.

Replicate `i`, starting at zero, uses transcript
`SHA256(UTF8("dsVert/joint-dp/statistical-oracle-transcript/v1/") ||
base_transcript[32] || uint64_be(i))`. Complete peer inputs in the output bind
chunk geometry, commitments, release hash, bounds, scaling and sampler domain.
The battery validates the active plan and its actual implementation allowance.
Its default mode now exercises the production v4 fallback; `--ideal-sampler`
retains the separate ideal-reference mode. Synthetic records preserve public
test seeds and the exact integer draws for independent replay. They do not
read or export deployment noise roots.

## Frequency selection

The Frequency planner command `joint-dp-frequency-backend-select-v2` compares
the exact v4 fallback with the existing Gaussian candidate before protected
material or seeds are read. Gaussian unavailability, including zero delta,
is explicit in its signed selection metadata. Selector v1 remains a reader
and runtime compatibility path for finite v3 artifacts. New R selection
summaries use `dsvert-frequency-backend-selection-v3`; exact plan summaries
use `dsvert-frequency-plan-summary-v2` and bind `wrap_certificate` instead of
a no-wrap hash. The Gaussian summary retains its finite-noise headroom fields.

The exact Frequency 95% accuracy method is
`exact_two_draw_exponential_union_modular_clamp_v1`. For
`k=ceil(log10(80*d))` and `T=ceil(3*k/alpha)`, the two-peer absolute-noise union
probability is at most `4*d*exp(-alpha*(T+1)) < 0.05`. Radius `2*T` is used only
when the public source upper bound plus that radius fits signed Ring128;
otherwise the fixed `[0,U]` clamp gives deterministic worst-case error `U`.
The reported radius is at most `U`; the certificate's `absolute_support=U`
therefore bounds released error, not unbounded sampler noise. Its
`release_tv_upper_numerator=0` describes the ideal exact noise, distinct from
representability and sum-wrap utility events.
