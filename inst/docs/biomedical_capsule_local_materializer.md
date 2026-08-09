# Biomedical capsule local materializer

## Scope

`dpCapsuleMaterializer.R` implements the internal, operation-independent local
producer for `dsvert-biomedical-capsule-workload-v7`. It is deliberately not
exported, does not end in `DS`, and is not registered as a DataSHIELD aggregate
or assign method. It never releases a value by itself: the registered source,
allocator, joint sampler, confidential finalizer and durable replay lifecycle
is the only consumer of its output.

The input is a validated capsule manifest plus snapshots that have already
passed the immutable snapshot resolver. The output is a fixed-length global
layout in which the local peer fills only blocks it owns and leaves every other
block at zero. The lexicographically first signed data owner and its first
signed dataset are the sole source of the admitted-unit count. This prevents a
vertical sum from counting the same cohort once per peer.

The implemented coordinate order is:

1. canonical admitted-unit count;
2. `(count, quantized sum, quantized sumsq)` for each selected sorted numeric
   column;
3. six pairwise-complete normalized moments `(n, sum x, sum y, sumsq x,
   sumsq y, cross)` for each selected numeric pair in the same signed
   dataset/owner, sorted by signed artifact ID;
4. each signed same-owner Gaussian model as `n`, the upper triangle of `X'X`
   in column-major order, `X'y` in signed design order, and `y'y`;
5. each deduplicated fixed-grid numeric histogram, sorted by primitive ID;
6. selected fixed-domain categorical marginals;
7. selected within-owner categorical pairs in column-major cell order; and
8. fixed-grid survival artifacts.

Describe analyses reference the shared numeric moments and histogram
primitives and therefore do not add duplicate coordinates.

## Server-authoritative primitive scope

The v7 workload always includes the canonical admitted-unit count. Primitive
selection is read only from the custodian's server policy; it is not a DSI or
analyst argument. The compatibility default is explicitly equivalent to:

```r
options(dsvert.dp.workload_scope = list(mode = "all_schema"))
```

`all_schema` includes univariate moments for every bounded numeric column,
every fixed-domain categorical marginal, and every same-owner/same-dataset
numeric-correlation and categorical pair. This preserves the previous result
layout, but its pair families have quadratic coordinate and sensitivity cost.

The recommended deployment mode is a canonical catalog, configured
identically at every pinned custodian:

```r
options(dsvert.dp.workload_scope = list(
  mode = "catalog_v1",
  numeric_moments = c("age", "bmi"),
  categorical_marginals = c("exposure", "outcome"),
  categorical_pairs = list(c("exposure", "outcome")),
  correlations = list(c("age", "bmi"))
))
```

Names are global names from the unanimously signed schema. Pair endpoints
must belong to the same signed dataset and owner; cross-owner pairs remain
declared through the signed `vertical_cross` specifications. Reversed pairs,
duplicates, and primitives already required by a signed describe, Gaussian,
survival, or vertical-cross specification are canonicalized and included only
once. No undeclared primitive contributes a coordinate or sensitivity term.

The manifest publishes `primitive_scope`, including the normalized selection,
its hash, possible-versus-included pair counts, per-family coordinate counts,
the projected vector size, and the exact outward sensitivity certificate. The
scope is bound into the source-context hash, capsule identity, authenticated
manifest cache, and every peer's signed build response. Source access accepts
only the exact manifest previously built by that server. Consequently a relay
cannot enlarge a workload, and differing peer catalogs fail manifest consensus
and local authorization before protected snapshots are resolved.

This is a scientific design tradeoff, not a request quota. `catalog_v1`
retains unlimited sticky replay and post-processing for every declared
artifact and scales as the declared univariates plus explicit pairs and model
cross-products. Adding a genuinely new primitive requires a new immutable
capsule authority, consumes a new allocator lifetime unit, and composes as a new
DP release. `all_schema` trades poorer utility and larger runtime/transport for
schema-wide exploratory flexibility.

### Versioned workload migration

No scope configuration change is required: an absent scope and an explicit
`list(mode = "all_schema")` still select the same statistics. The current v7
workload signs the registered-lifecycle contract and the bounded lifetime
policy into capsule identity; it never reinterprets an earlier capsule in
place. Earlier published releases remain immutable replay records. A v7 capsule
must nevertheless reserve one available lifetime unit before this materializer
can read protected snapshots. Large-schema deployments should install one
identical `catalog_v1` option at every pinned peer before creating it. Once a
catalog capsule exists, every declared analysis can be replayed without a
request counter or accuracy decay; genuinely new sufficient statistics require
a new capsule and therefore another available lifetime unit.

## Contribution semantics

- Admission is patient-level, capacity-bounded, and rejects malformed patient
  identifiers, cohort overflow, or excess records per patient.
- Numeric rows are clipped to signed bounds before one within-patient mean is
  formed. `NA`, `NaN`, and infinite values have no numeric contribution.
- Numeric pair moments include a unit only when both separately collapsed
  values exist. A missing pair is the zero contribution, so the natural
  per-pair L1/L2 bounds are 6 and `sqrt(6)` under both add/remove and
  replace-one adjacency. Cross-owner products remain
  `reserved_not_materialized`.
- A Gaussian unit is complete only when the separately clipped and
  patient-collapsed outcome and every signed predictor exist. Its design has
  an explicit signed intercept choice; all variables are normalized to
  `[0,1]`, and each monomial is independently rounded to the common public
  integer grid. For `q` design terms the block has
  `C = 1 + q(q+1)/2 + q + 1` coordinates. Its natural sensitivities are `C`
  and `sqrt(C)`, and its raw integer sensitivities are
  `1 + (C-1)*scale` and `sqrt(1 + (C-1)*scale^2)`, for both add/remove and
  replace-one adjacency. Missing complete cases are the zero vector, so the
  all-zero/all-one endpoints attain these conservative bounds.
- With an intercept, the noisy complete-case count and noisy `X'X[1,1]` are
  intentionally separate coordinates. The count supplies the reported count
  and public moment clamp; `X'X[1,1]` governs the model solve. They are never
  averaged or silently reconciled.
- A numeric unit with no finite value contributes to the fixed invalid
  histogram bin. Finite out-of-bound values are clipped; they do not select a
  data-dependent error branch.
- A categorical unit contributes once only when its valid repeated rows agree
  on one fixed-domain level or joint cell. Missing and out-of-domain rows are
  ignored; conflicting valid values contribute zero.
- Survival selects the earliest valid event, otherwise the latest valid
  censoring row, followed by fixed cause and entry-time tie-breaks. Invalid
  units enter one fixed quality bin. The rule is invariant to row permutation.

Consequently protected missingness and malformed values never change vector
shape or choose a visible error phase. Schema/type failures and immutable
snapshot-binding failures still fail closed because they are contract or
infrastructure failures, not query-history gates.

## Numerical certificate

All materialized coordinates and L1 sensitivity bounds are exactly
representable integers. Every positive binary64 addition, multiplication and
square-root used by an L2 certificate is rounded outward immediately under the
`per_operation_outward_binary64_guard_v2` rule. The relative guard is
negligible for utility but prevents a published floating-point sensitivity
from falling below the corresponding exact neighbour norm through accumulated
rounding or an unfavourable evaluation order.

Mechanism choice is also public and deterministic. Gaussian is eligible only
when the capsule delta is strictly greater than the existing TV-transfer bound
`coordinate_count * (1 + exp(epsilon)) * 2^-40`, evaluated conservatively, and
the canonical selector chooses it only when its simultaneous 95% radius is
strictly smaller than Laplace. Otherwise the capsule uses discrete Laplace and
the exact L1 bound. A positive but tiny deployment-default delta (including
`2^-100`) remains reserved for sampler implementation slack, so
`uses_delta = TRUE`, but never sends an underfunded Gaussian plan to the
sampler. Zero delta retains the pure-DP Laplace contract.

The local object binds the capsule ID, logical snapshot, source-context hash,
peer, coordinate-order hash, and private resolved-snapshot fingerprints. Its
values are committed in 65,536-coordinate blocks, then reduced to one
purpose-domain-separated hash suitable for a future peer signature or MAC.
The hash is an authenticatable commitment, not itself authentication.

Materialization is deterministic for the same admitted snapshot and workload.
It does not inspect composition history, number of previous requests, epsilon
remaining, or a release counter. Reuse therefore cannot cause denial or
accuracy decay at this layer.

## Memory and performance

Admission is cached once per local dataset. Each selected bounded per-unit
numeric column is collapsed once and reused by its univariate moments,
histograms, same-owner pairs and Gaussian designs. Once the univariate moments
and every declared histogram for a column are complete, the cache drops its
finite-only `values`, `present` reference and bounds reference. Pairs and
Gaussian designs retain only `unit_values` and `valid`. For `n` valid admitted
units and `p` local numeric columns, this removes at least the `8 * n * p`
bytes occupied by the distinct finite-only double vectors (plus list
overhead); the one admission `present` vector remains shared per dataset.

A Gaussian artifact with `q` design terms costs
`O(admitted_units * q^2)` time and `O(q^2)` output coordinates;
the implementation never constructs an individual-level cross-product table.
Across a catalog-scoped workload this makes materialization linear in
protected rows plus explicitly declared pair/model products, while retaining
bounded patient-collapsed numeric state. Value
commitments are hashed blockwise rather than serializing the full result
twice. The returned state is proportional to the public capsule coordinate
count. Only explicit `all_schema` expands all same-owner pairs quadratically.

The reproducible development benchmark is
`experiments/capsule-materializer-memory/benchmark.R`. It compares the compact
path with the former full-cache behavior by replacing only the compaction
helper, warms both paths, alternates execution order, and reports three-run
medians. On 2026-08-08 it measured the following all-schema cases; every
serialized local material, coordinate vector, value commitment and
authenticatable commitment was byte-identical:

| admitted units | numeric columns | pairs | full cache | compact cache | distinct `values` removed | full / compact median |
|---:|---:|---:|---:|---:|---:|---:|
| 2,000 | 8 | 28 | 390,896 B | 195,760 B | 128,384 B | 0.202 / 0.209 s |
| 8,000 | 16 | 120 | 3,085,744 B | 1,543,472 B | 1,024,768 B | 0.622 / 0.617 s |
| 20,000 | 24 | 276 | 11,540,592 B | 5,771,184 B | 3,841,152 B | 1.757 / 1.815 s |

`object.size()` counts references conservatively and can count shared objects
more than once, so `distinct values removed` is the conservative unique-vector
reduction. The timings show unchanged computational complexity, not a claimed
speedup; the practical gain is lower live heap pressure and therefore less
risk of garbage-collection or swapping stalls on larger workloads.

The next source-transport stage processes that vector in fixed public
8,192-coordinate chunks. Each chunk is split over Ring128 with OS CSPRNG bytes,
encrypted independently to the two pinned noise peers, and committed as a pair
before it becomes fetchable. `dsvertDPCapsuleSourceChunkDS()` returns both
recipient envelopes in one canonical bundle, so transport needs one DSI fetch
per source/chunk rather than two. The bundle has a 768 KiB portable response
bound; storage pressure is a byte bound and never a query, history, epsilon, or
privacy-budget gate.

A 2026-08-01 arm64 development microbenchmark over 1,000,000 coordinates used
123 chunks and real packaged X25519/AES-GCM encryption for both recipients. The
split/encrypt/envelope loop took 12.95 s (77,220 coordinates/s), produced
32,332,580 raw ciphertext bytes and 43,391,902 relay JSON bytes (43.39 bytes per
coordinate for both recipients). This is about 344.5 KiB per two-envelope
bundle before its small fixed wrapper, below the 768 KiB bound. The input vector
was 8,000,048 bytes and each recipient's Ring128 share was 16,000,000 bytes.
Process RSS was 393.1 MB versus a 235.4 MB loaded-development baseline; the
increment includes R allocator high-water state and subprocess overhead. This
is a transport microbenchmark, not an end-to-end DSI/network/SQLite benchmark.

## Implemented confidential source boundary

The exact local object is immediately split into two uniformly random additive
Ring128 shares. Only opaque X25519/AES-GCM ciphertext and fixed public metadata
cross the analyst relay. Each designated peer durably aggregates its own share
in canonical owner/chunk order and passes it only to the registered joint-vector
sampler. Retries replay the same persisted key, ciphertext or acknowledgement
and never resplit a released chunk. K=3 and larger owner sets do not give
non-designated owners a recipient share.

## Registered release boundary and remaining coverage

The local object contains exact protected sufficient statistics. It must never
be returned, logged, or sent through the analyst relay in plaintext. The v6
manifest therefore binds exactly one registered
materialize/share/sample/finalize/replay lifecycle. Its
`declared_workload_fully_materialized = TRUE` statement applies only to the
coordinates actually included in the signed vector; it is not a claim that
every analysis family in the package is implemented. The separate
`package_family_coverage_complete = FALSE` statement records that limitation.
Live Opal or Armadillo execution is also not asserted by a signed manifest:
`execution_state` requires the client runtime preflight, pinned-peer handshake,
registered-surface checks and backend capability checks for each run.

Source tickets, summaries, ciphertext envelopes, bundles and acknowledgements
retain `ready_for_sampling = FALSE`. They are raw confidential intermediates,
not independent sampling authorities or DP releases. Only the cross-signed
allocation plus the two-peer sampler and common confidential finalizer can
produce the public vector.

Secure producers are registered for the included same-owner coordinates,
fixed-domain cross-owner categorical tables and signed cross-owner Gaussian
models. Numeric cross moments, numeric-by-category summaries and iterative
model cross terms that lack a producer remain outside the coordinate vector or
cause the consuming method to fail closed; they are never represented by a
silent zero or substituted estimator.

The ordinary local materializer covers same-owner primitives. It leaves a
declared cross-owner categorical release block at zero locally and fills it
only from the authenticated exact-protocol result shares immediately before
joint noise. Other requested vertical-cross families remain excluded and
explicitly marked `reserved_not_materialized`; none is silently substituted.
