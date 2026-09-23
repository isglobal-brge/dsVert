# Exact discrete-Laplace sampler core

Status: implemented and unit-tested, **not selected by a production plan**.
The requested per-peer cap/no-wrap contract remains unresolved in
`DESIGN_PURE_LAPLACE.md`. The active v3 finite sampler and its positive delta
remain unchanged. No existing artifact acquires a pure-DP guarantee.

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
stream pseudorandomness assumption. The intended exact-mechanism metadata is
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

## Representation and the unresolved release boundary

For signed width `W`, `B=2^(W-1)`, and range `[-B,B-1]`, a draw is outside
the range with probability exactly `q^B`. Across two peers and `d` coordinates,
the union bound is `min(1,2*d*exp(-alpha*B))`. It is positive, even if a
floating-point evaluation underflows. The decimal-bound helper rounds outward
using `exp(3)>10` and retains arbitrarily large scientific decimal exponents.
For `alpha>=2^-100`, `d<=1000000`, `W=128`, its bound is at most
`1e-44739235`, far below `2^-256`.

Representability of individual draws does not establish headroom for their
sum. Two signed 128-bit draws need more than Ring128. Clipping the draws
changes the conditional privacy law; a small coupling error cannot be called
pure DP by storing it outside mechanism delta. Unbounded integer draws reduced
modulo Ring128 preserve the ideal pure-DP theorem as postprocessing, but need
a nonzero utility wrap bound rather than deterministic no-wrap certification.
No production admission rule or replacement certificate is enabled yet.

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
The battery validates the active plan and uses its actual implementation
allowance. Until production integration is resolved, this is v3 evidence,
not evidence that the exact sampler has been deployed.
