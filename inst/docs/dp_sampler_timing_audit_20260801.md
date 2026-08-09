# dsVert DP sampler timing audit

Status: output-DP plus a fixed logical worker transcript for the productive
dyadic Gaussian backends; sampler/egress wall-clock timing is not a promoted
privacy capability. Audit date: 2026-08-01, updated 2026-08-02.

## Scope and result

This audit covers the deterministic granular Laplace sampler in
`k2_dp_noise.go`, the approximate Gaussian sampler in `k2_dp_gaussian.go`,
the productive finite binary-geometric vector Laplace sampler in
`k2_joint_dp_vector_convolution_v3.go`, and the productive dyadic
discrete-Gaussian sampler plus its legacy exact cross-oracle in
`k2_joint_dp_discrete_gaussian_v1.go`. All four productive sampler families
use a purpose-bound
HMAC/HKDF-SHA256/ChaCha20 stream, so the same canonical release keeps the same
draw and cannot be rerolled while its noise root and privacy epoch persist.

Two legacy/local sampling paths have work that is not independent of that draw:

- `halfGeometric()` reads bytes until it sees a non-zero byte;
- `i63n()` rejects 63-bit candidates outside the largest exact multiple;
- granular Laplace follows an adaptive probabilistic search and can repeat the
  zero/negative-sign case;
- approximate Gaussian repeats rejection proposals until one is accepted.

The productive vector Laplace v3 path is different: it has finite public loop
bounds (`uniform_bits` is 128 or 256 and `binary_geometric_bits <= 63`). Its
private-word comparison, Bernoulli bit assembly, signed difference, Ring128
addition and fixed 16-byte serialization now use fixed-width `uint64` limbs.
They contain no loop bound, allocation size, early-exit comparison or branch
selected by the private word, noise or source share. This is an
algorithmic/compiled-hot-path result, not a claim that Go, the OS or DSI is a
constant-time execution environment. The productive full discrete-Gaussian v2
path now also has finite public work shape: one fixed-width dyadic word plus one
sign byte followed by a complete sequential scan of every fixed-width CDF
threshold per coordinate. Byte-wise subtraction propagates a borrow through
the whole word and a mask selects the first hit; there is no rejection, retry,
early acceptance, secret-indexed table read or data-dependent message size.
Its public table is enclosed with exact rational intervals and its finite CDF
TV is charged separately from the ideal-law tail truncation. The plan therefore
records `transcript_dp_claim=true` only for public work count, rounds, payload
count and payload lengths. It separately records
`host_constant_time_claim=false` and `physical_timing_dp_claim=false`: Go,
allocation, GC, the OS, DSI completion and retransmission cadence are not a
constant-time environment.

The R capsule validator treats the complete v2 planner record as a versioned
wire contract rather than accepting unknown fields.  In particular it checks
the following execution/threat-model fields emitted by Go:

- `sampler_full_scan_steps == sampler_magnitude_count` and
  `sampler_cdf_table_bytes == sampler_magnitude_count *
  sampler_random_bytes_per_coordinate` certify the public full-scan geometry;
- `nominal_variance_multiplier=2` and
  `nominal_standard_deviation_factor=sqrt(2)_relative_to_one_full_draw`
  describe the two independent complete-noise draws;
- `at_least_one_honest_noise_peer=true`,
  `maximum_colluding_noise_peers=1`, `adversary_view`,
  `adversary_view_privacy_argument` and
  `source_share_hiding_precondition` bind the semi-honest two-peer threat
  model; and
- `sampler_branches_on_private_randomness=false`,
  `logical_transcript_fixed_shape=true`, `transcript_dp_claim=true` and
  `physical_timing_dp_claim=false` distinguish the branchless algorithm and
  fixed logical transcript from any unsupported host-timing claim.

Any omission or semantic substitution in these fields makes the Gaussian
backend unavailable; it must never be silently reinterpreted as the same v2
certificate.

The other samplers remain variable-work, and the runtime still does not claim
that request timing is part of its DP transcript. This matters because a
precise estimate of additive noise, combined with the released noisy value,
could reveal more about the unnoised statistic than the output-DP proof allows.
Sticky noise prevents averaging different draws; it does not turn a repeatable
timing signal into a safe signal.

The current DSI route does not hide this signal. The server waits synchronously
for the local sampler process and the client/relay waits for the corresponding
DataSHIELD aggregate response. The relay can therefore observe at least
per-phase completion time, availability, retries and failure class, in addition
to public request size. TLS protects contents in transit but does not make that
wall-clock transcript private. A pair `(noisy_value, timing(noise))` is not
covered by a theorem proved only for `noisy_value`, even when the timing
marginal itself is independent of the protected statistic.

The productive vector Laplace v3 hot path was replaced without changing its
probability law or sticky bytes. Tests compare both 128- and 256-bit plans,
boundary/random comparisons, Ring128 arithmetic and multiple valid chunk
geometries byte-for-byte against the previous `math/big` implementation. A
change in chunk geometry remains a different v3 stream because v3 binds
`chunk_start`, `coordinate_count`, shifts and bounds; rechunk-invariant noise
would require a coordinated v4 domain rather than a silent compatibility
change.

The former exact CKS/IBM rejection sampler remains only as a cross-language
oracle. It is not reachable from the productive v2 worker. V2 is versioned as
a dyadic, truncated, TV-bounded discrete Gaussian and does not claim exact
rational sampling. Its planner splits the implementation allocation between
tail truncation and dyadic-CDF approximation, and its 95% simultaneous radius
also reserves the two-peer ideal-to-implemented TV transfer.

## Reproducible measurement

Run:

```text
cd inst/dsvert-mpc
go test -run '^$' -bench DPSamplerTiming -benchtime=750ms -count=3 ./...
```

`k2_dp_timing_benchmark_test.go` selects 256 deterministic coordinates in
each magnitude bucket while holding the 32-byte seed and all public mechanism
parameters fixed. Its test-only audit model is checked against the production
draw for 4,096 Laplace and Gaussian coordinates. Wall time is intentionally
reported without a pass/fail threshold because scheduler noise would make
such a test misleading.

This legacy benchmark does not measure either productive vector backend. Its
table must not be cited as evidence about them. The v2 Gaussian benchmarks
separate fixed-CDF draw cost, public table construction and the complete noise
worker:

```text
go test -run '^$' \
  -bench '^BenchmarkJointDPGaussian(FixedSampler8192|FixedTableBuild|FixedNoise8192|LegacyExact8192)$' \
  -benchtime=1x -count=3 -benchmem
```

On Apple M2 / Darwin arm64 (updated after the oblivious scan on 2026-08-02),
the medians were 4.610 ms for 8,192 bare fixed-CDF draws, 1.139 ms for a
257-entry public table, 30.329 ms for the complete v2 8,192-coordinate noise
worker, and 113.167 ms for the legacy exact CKS oracle. Complete v2 sampling
was therefore 3.73 times faster in this fixture. It allocated about 21.98 MB
in 247,514 allocations versus 71.35 MB in 4,038,955 allocations for the
oracle. These figures are throughput evidence, not a constant-time or
cross-platform guarantee; table cost is a function only of public parameters
and is paid once per worker chunk.

Apple M2 / Darwin arm64 evidence from 2026-08-01:

| Mechanism bucket | Mean absolute draw | Mean entropy bytes | Mean adaptive work | Observed ns/draw (3 runs) |
|---|---:|---:|---:|---:|
| Laplace, `abs <= 1` | 0.516 | 378.8 | 40.96 search rounds | 5,065-5,191 |
| Laplace, `abs >= 5` | 5.711 | 444.9 | 48.31 search rounds | 5,100-5,322 |
| Gaussian, `abs <= 1` | 0.648 | 312.6 | 16.38 proposals | 3,147-3,278 |
| Gaussian, `abs >= 8` | 8.973 | 293.0 | 15.31 proposals | 2,980-3,408 |

The elapsed ranges overlap, especially for Gaussian, and are not evidence of
a remote reconstruction exploit by themselves. The operation counts do show
that work shape is draw-dependent. End-to-end DSI, R, cache, ledger, GC,
scheduler and network noise may mask or amplify it; none provides a formal
privacy boundary.

For the productive vector convolution v3 route, the reproducible throughput
benchmark is:

```text
go test -run '^$' -bench '^BenchmarkJointDPVectorConvolutionSample8192$' \
  -benchtime=3x -count=3
```

On the same Apple M2 / Darwin arm64 host, the fixed-limb path reduced median
time for 8,192 coordinates from 15.229 ms to 11.249 ms, allocations from
122,911 to 73,755 and allocated bytes from about 5.769 MB to 4.556 MB. The
optimized arm64 assembly uses full subtraction/carry chains (`NEGS/SBCS/NGC`),
branchless bit assembly, and Ring128 `ADDS/ADCS`; observed conditional branches
are loop/bounds or public-shift handling. This supports the source-level
constant-work audit on this target, but is not a cross-platform or DSI timing
certificate.

## Productive vector convolution Laplace v3

This finite sampler already charges the total-variation effect of its public
binary-geometric truncation and dyadic threshold rounding to
`implementation_delta`. Replacing variable-width `math/big` operations with a
fixed-limb implementation preserves every Bernoulli threshold decision, hence
requires no new privacy transfer and changes neither accuracy nor sticky
outputs.

The sampler layer can therefore be implemented with finite constant work,
unlike the exact Gaussian route. Full transcript-DP still requires fixed-size
envelopes, normalized failures and a public egress schedule. Runtime validation
also remains part of the trusted boundary: compiler version, architecture,
garbage collection, scheduling and DSI completion timing are not certified by
the limb arithmetic alone.

## Why a local fixed-round patch is not promoted

### Pure granular Laplace

The two-sided geometric law has unbounded support. A sampler consuming a
fixed finite amount of entropy cannot reproduce that law for every draw.
Truncating, substituting a fallback, or conditioning successful responses on
a finite cap changes the released distribution unless an exact finite-output
construction is separately proved. Any total-variation deviation would need
an explicit `delta_timing` allocation; it cannot continue to be labelled the
current pure (`delta = 0`) Laplace mechanism.

Final output clipping gives a finite output alphabet, but that observation is
not enough: an exact, numerically stable sampler for the clipped distribution
would still need a proof that it matches the current mechanism for every
admissible statistic and parameter. No such proof or implementation is
present.

### Approximate Gaussian

A fixed number of outer rejection proposals could evaluate every proposal and
select the first accepted one. Conditional on at least one acceptance, the
usual rejection argument can preserve the target proposal law. It does not
solve the variable `halfGeometric()` and `i63n()` work inside each proposal.
A finite inner cap, biased integer reduction, fallback draw, or sampler abort
therefore needs:

1. a uniform lower bound on acceptance over the full admitted parameter
   domain;
2. a total-variation/abort bound for every capped primitive and coordinate;
3. composition of that bound with the existing scalar `2^-40` Gaussian
   implementation bound and the release delta; and
4. distribution, sticky-replay, accuracy and performance validation.

The existing `2^20` Gaussian iteration ceiling is a fail-closed liveness
guard, not fixed-work padding. It returns no partial release and retrying the
same sticky release does not obtain new randomness. It must not be cited as a
constant-time property.

### Productive dyadic discrete Gaussian v2

The full v2 worker consumes exactly
`sampler_random_bits_per_coordinate/8 + 1` bytes per coordinate and reads
exactly `sampler_full_scan_steps * sampler_random_bytes_per_coordinate` public
CDF bytes. The single candidate is a power-of-two dyadic word, so there is no
modulo rejection or all-candidates-failed event. The target-law deviation is
the exact table-TV certificate recorded in `implementation_delta`. Exhaustive
boundary tests compare the scan against the original exact `big.Int` CDF, and
an exhaustive two-byte test checks the fixed-width borrow comparator. This
closes logical work/I/O-shape and unbounded-rejection gaps. It does not promote
host timing or end-to-end DSI timing.

The reproducible formal-Poisson fallback benchmark is:

```text
cd inst/dsvert-mpc
go test . -run '^$' \
  -bench '^BenchmarkJointDPGaussianObliviousPoissonFallbackP(1|8)$' \
  -benchtime=1x -benchmem
```

Apple M2 / Darwin arm64 evidence from 2026-08-02:

| Coordinates | Time/op | CDF entries/coordinate | CDF bytes/coordinate | Heap bytes/op | Allocations/op |
|---:|---:|---:|---:|---:|---:|
| 1 | 298,083 ns | 34,394 | 584,698 | 216 | 6 |
| 8 | 2,460,250 ns | 36,324 | 617,508 | 1,664 | 48 |

The CDF table is built from public parameters before the timed sampling loop;
the CDF-byte column reports its fixed resident/read footprint, whereas
`B/op` reports allocations in the sampling loop. These are local throughput
measurements, not network or physical constant-time evidence.

## Promotion design for timing-inclusive privacy

A defensible timing-inclusive capability belongs at the release dispatcher
and egress boundary, not in a cosmetic sleep around one sampler:

1. Record a public service slot/deadline before admission and sampling start.
   Its schedule may depend only on public mechanism, coordinate-count and
   deployment classes.
2. Buffer the complete response and release a fixed-shape envelope only at
   that deadline. Admission, cache, sampler and error paths need the same
   externally observable class.
3. Prove a conservative overrun probability `beta` over every random and
   operational path in the public service class. If the real transcript is
   coupled to the fixed-egress transcript except on an event of probability at
   most `beta`, its total-variation transfer costs at most
   `(1 + exp(epsilon)) * beta` in delta. Include the union across both peers and
   every observable phase. Reserve that already-transfer-charged
   `delta_timing` before sampling; never borrow from the user's declared delta
   after the fact.
4. Bind deadline class, padded envelope length and `delta_timing` into the
   canonical query, global receipt and sticky release record.
5. If an overrun occurs, let the exact sampler continue and persist/resume the
   same deterministic stream. Its eventual value law must remain unchanged. A
   late envelope or detailed overrun state is allowed to differ from the ideal
   fixed-egress transcript only inside the event already covered by `beta`; it
   must never mint a fresh seed, substitute a fallback or silently reroll the
   release.
6. Validate the entire R/Go/OS/DSI path under load. Go timers, garbage
   collection and an ordinary scheduler are not constant-time primitives, so
   microbenchmarks alone cannot promote the claim. A fixed-window asynchronous
   release service or independently validated padding gateway is the more
   credible deployment design.

Until those conditions are implemented and independently tested, the honest
contract is: values and their stated mechanism accounting are covered by the
output-DP claim; timing, availability, cache state and detailed failure
transcripts are excluded. No fixed-egress scheduler, timing delta, constant-rate
gateway or full-transcript DP guarantee is currently implemented.
