# Gaussian sampler performance and explicit fallback

## Decision

The exact-GC one-draw Gaussian route remains sealed. It is numerically and
cryptographically useful as a high-utility reference, but its public CDF lookup
is not scalable enough to promote. The signed selector now prefers it when the
public no-wrap and resource certificates admit it; otherwise it automatically
selects the
`independent_full_global_dyadic_discrete_gaussian_tv_bounded_ring128_v2`
fallback. The selected backend, utility cost and observable-shape claims are
explicit and cross-signed by all K custodians; there is no silent mechanism
substitution.

The fallback makes two independent complete calibrated draws, one at each
pinned noise peer. Its nominal variance is exactly twice the variance of one
full draw and its nominal standard-deviation factor is `sqrt(2)`. This utility
cost is signed in the plan; it is not described as the one-draw mechanism.

## Why binary search does not make the GC logarithmic

The reference code emits a balanced decision tree, so its logical depth is
`ceil(log2(M))`. In a Boolean circuit both secret branches must nevertheless
exist. With no secret-indexed public RAM/ORAM primitive, an arbitrary public
CDF with `M` intervals therefore compiles to `M-1` 128-bit comparisons per
coordinate. Replacing the source syntax with a secret index and a mux tree
only moves the same linear work into the mux network.

The plan now states all four facts explicitly:

- the lookup model is a public-constant threshold tree;
- logical depth and circuit comparison count are separate fields;
- secret-indexed public RAM is unavailable;
- no logarithmic circuit-size claim is made.

The measured Phase-1.6 shapes on Apple M2 were:

| Shape | Compile wall time | Go allocation | Gates | Non-XOR | Garbled tables |
|---|---:|---:|---:|---:|---:|
| p=1, sensitivity=256 | 3.331 s | 2.409 GB | 7.71 M | 2.20 M | 70.5 MB |
| p=2, sensitivity=363 | 21.493 s | 6.582 GB | 22.28 M | 6.37 M | 203.7 MB |

The p=2 peak is no longer admitted as one circuit: the conservative compiler
allocation ceiling is 6 GiB, which makes that plan use one-coordinate chunks.
This is a per-circuit resource bound, not a request or history quota; every
coordinate may still run, and sticky absolute-coordinate derivation preserves
the same draw across chunking.

Full-vector cost projections at epsilon=1, delta=1e-6 and sensitivity=363 are:

| p | CDF comparisons/coordinate | Logical depth | Projected gates | Projected compiler allocation | Admitted chunk |
|---:|---:|---:|---:|---:|---:|
| 1 | 12,192 | 14 | 15.63 M | 5.00 GB | 1 |
| 2 | 12,424 | 14 | 31.84 M | 10.19 GB | 1 |
| 8 | 12,876 | 14 | 131.93 M | 42.22 GB | 1 |
| 64 | 13,526 | 14 | 1.109 B | 354.77 GB | 1 |

These are conservative planner projections, not measured allocations. They
show why rechunking controls peak memory but cannot make total one-draw GC work
sublinear in `p*M`.

## Scalable two-full-draw route and adversary view

Each designated peer receives a computationally hiding additive aggregate
share and generates one complete-epsilon, complete-global-L2-sensitivity,
finite-support/dyadic-CDF discrete-Gaussian vector draw from its sticky private
seed. The final release is the signed/clamped sum of both noised shares.

For an analyst colluding with at most one semi-honest noise peer, condition on
that peer's simulatable source share, seed, draw and protocol transcript. Its
known contribution is then a fixed translation. The other peer's independent
complete mechanism remains `(epsilon, delta)`-DP; translation, adding the known
draw, signed decoding and public clamping are post-processing. The two
conditional guarantees are symmetric, so release implementation delta is the
maximum of their equal per-peer bounds, not their sum. This argument requires:

- at least one of the two designated peers is honest and non-colluding;
- a single pre-noise aggregate share is simulatable without the protected
  query;
- authenticated semi-honest fan-in prevents a corrupt peer from injecting an
  extra data-dependent release channel;
- seeds and sticky stream identifiers remain private and release-stable.

The plan now serializes this adversary view, its source-share-hiding
precondition, the collusion threshold and the `sqrt(2)` utility certificate.
A distribution-independent exact-rational hockey-stick regression verifies
that conditioning on any fixed known-peer contribution preserves both directed
divergences.

The full sampler now scans every fixed-width CDF entry sequentially and uses a
byte-borrow/mask first-hit selection. Consequently its logical work, reads,
rounds and payload sizes depend only on public plan geometry. It still makes no
host constant-time, wall-clock or retransmission-timing claim.

Measured local scan benchmarks (`-benchtime=1x -benchmem`, Apple M2 / Darwin
arm64, 2026-08-02) were:

| p | Time/op | CDF entries/coordinate | CDF bytes/coordinate | Heap bytes/op | Allocations/op | Secure CDF gates |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 298,083 ns | 34,394 | 584,698 | 216 | 6 | 0 |
| 8 | 2,460,250 ns | 36,324 | 617,508 | 1,664 | 48 | 0 |

Reproduce with:

```text
go test . -run '^$' \
  -bench '^BenchmarkJointDPGaussianObliviousPoissonFallbackP(1|8)$' \
  -benchtime=1x -benchmem
```

The public CDF table is constructed before the timed loop. Its resident/read
footprint is reported separately from the small per-sample heap allocation.
Timings are benchmark evidence for this machine, not universal latency or
physical constant-time guarantees.

The exact full-fallback range guard for p=8 measured 60,667 ns/op, 31,061
gates, 12,545 non-XOR gates and 41,304 heap bytes/op on the same host. Reproduce
with:

```text
go test . -run '^$' \
  -bench '^BenchmarkFormalGLMPhase16FullRangeGuardCircuitP8$' \
  -benchtime=1x -benchmem
```

## Promotion blockers (exact inventory)

The formal GLM release remains internal even though the numeric, binding,
K=2/3/4/5 and local productive paths are executable. Promotion requires all of
the following evidence; none may be inferred from the local tests above:

1. A public R/DSI frontdoor that is bound end-to-end to the signed Phase-19
   token, selector, local source receipts and durable release receipt, without
   exposing any internal prepare/worker command as an AggregateMethod.
2. A real multi-process, multi-site DSI test across supported connector classes,
   including retry/reconnect, backpressure, short writes, duplicate delivery,
   crash recovery and byte-identical sticky replay.
3. A fixed public envelope/round contract at the DSI boundary and documented
   normalization of remotely visible failures. The current logical transcript
   certificate explicitly excludes wall-clock completion, scheduler behavior,
   polling and retransmission cadence.
4. If physical timing-inclusive DP is claimed, a separately proved fixed-egress
   design with an allocated timing delta and validated overrun bound. Ordinary
   Go/R/OS scheduling is not such a primitive.
5. Performance evidence on representative large biomedical datasets and WAN
   conditions. The current pure-Boolean exact-GC iteration kernel is fixed and
   correct but is not yet replaced by, or benchmarked against, the planned
   mixed arithmetic/Boolean kernel.
6. A complete green Go and R package suite, packaged-binary checksum refresh,
   cross-platform builds, `R CMD check`, and an independent review of the
   formal privacy/numeric certificates and stated semi-honest threat model.

Until these are closed, `production_ready=false`, no formal GLM command is a
runtime capability, and no `formalGLM*` method belongs in the exported or
AggregateMethod surface.

## PoPETs 2025 OT-table route

Kii, Ichikawa and Miura, “Lightweight Two-Party Secure Sampling Protocol for
Differential Privacy,” PoPETs 2025, DOI
[`10.56553/popets-2025-0003`](https://doi.org/10.56553/popets-2025-0003), is a
strong candidate for a future compact joint sampler. Protocol 3 has Alice mask
and randomly permute a small public table, Bob choose a random index, and both
use 1-out-of-L OT to obtain additive noise shares without either learning the
selected value. Theorem 7.1 proves semi-honest security in the SFE/OT hybrid.
The paper's Algorithm 2 constructs finite tables whose N-fold convolution is
certified with hockey-stick divergence; it reports 7.4 MB for `(1, 2^-40)`
versus 183 GB for a naive table.

It is not a drop-in proof for this Gaussian route:

- the evaluated mechanism is scalar integer-L1 discrete Laplace (their
  experiments fix sensitivity 1), not the multivariate L2 discrete Gaussian;
- the paper explicitly does not prove its proposed batched-OT variant;
- dsVert currently has reviewed 1-out-of-2 IKNP/KOS building blocks, not a
  reviewed, purpose-bound 1-out-of-L sampler contract;
- a vector adaptation needs its own exact PMF/hockey-stick or zCDP proof,
  finite-support transfer, utility certificate and K=2/K>=3 role binding;
- Alice's mask/permutation and Bob's index must be deterministically sticky per
  release and absolute coordinate, identical on retry but domain-separated
  across coordinates/releases, without allowing either side to reroll.

Consequently no OT-table Gaussian claim or code path is promoted here. The
paper supplies a credible next implementation direction; treating its scalar
Laplace proof as a Gaussian-vector proof would be a silent mechanism
substitution and is rejected.
