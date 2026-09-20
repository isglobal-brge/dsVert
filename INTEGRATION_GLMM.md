# Cycle 14 Poisson source wiring — 2026-09-20

Poisson now reuses the durable GLMM variance-grid path with authenticated
family and maximum-outcome fields. Exact full-width q0 and f50 guards retain
counts 0 through the signed maximum (1..4), including missing-row rejection.
The router applies the larger bound only to the outcome column; features
remain in [0,1]. The corrected private-carry Ring128→192 conversion is unchanged.

Node stages use the retained range-reduced exp producer. GH5 selection omits
factorials and retains the private candidate-independent +2/live-row shift.
The mirrored composition descriptor is grouped_poisson_glmm_gh5_v1.json,
SHA256 1fe5a19c74969134731d5d3210b9646e52783192570256806e0ac7a1e4ae9c94.
The p3/J4 and n2000/C500/B4 measurement domain, variance-major candidate order,
source/contract hashes, private terminal validity and sticky DP lifecycle are
bound end to end. Fixed contracts and omitted-default binomial native/source
serialization retain their prior bytes.

Local focused native/source/router/wire tests and mirrored R contract/reader
tests pass. The release integer oracle agrees with the retained full-likelihood
oracle translated before quantization/clipping at g8/g16/g18. Three existing
server reference-dependent tests require the tagged oracle on pod4. The isolated Poisson source snapshot
d9348bf/d27c566 now has four rebuilt/checksummed runtimes and a passing pod4
focused native suite (768.165s; one opt-in n2000 router-capacity test skipped).
Its independent integer oracle passes; tagged R focused proof, signed n4 smoke,
n2000 capacity/recovery and full paired proofs are tracked by a detached gate. No Poisson promotion is claimed.

Cycle14 prioritizes code wiring over waiting for original release drivers.
The original LMM/binomial frozen snapshots remain unchanged and unpromoted;
their measurements retain their original source/runtime identities. Exact
logs, subsequent build/smoke/queue identities and pending gates are in the
workspace integrator-evidence/cycle14-20260920 directory and STATUS_INTEGRATOR.md.

---

# Cycle 12 continuation harvest — 2026-09-20

Documentation-only checkpoint; production source/runtime pair remains
ba436a1/496c053. At 23:56:17 UTC, original frozen n2000 K2 drivers are active:
LMM b3a2b1d/e748f05 has 229 committed stages per authority; binomial
56cc3dd/496c053 has 16. All 2,500/2,526 respective frozen files rehash correctly.
Neither has complete release metrics. K3/K5/recovery/paired remain unstarted.
No promotion or n2000 capacity is established. Old-runtime measurements retain
their original identities. The ba436a1 paired suite is still running server
tests; client tests are queued. Existing detached collectors remain active.

The workspace's integrator-evidence/cycle12-20260920/CONTINUATION_HARVEST.json
pins the immutable original-driver capture and the newer paired observation.
STATUS_INTEGRATOR.md and progress.json retain pending gates. No production
change, frozen-snapshot modification, relaunch, tag, push or thesis edit.

---

# Cycle 12 public-program reuse — 2026-09-20

The binomial stage executor now compiles each public 32-coordinate program
once per stage attempt and replaces it for the final short chunk. This removes
repeated compilation measured in an isolated native diagnostic. Live/outcome
guards, predictor, softplus, negative exponential and guarded logsum retain
their exact generated program bytes. Each chunk still creates fresh protocol
sessions, masks, garbling and OT state; nothing private is cached.

Pod4 native proof passes source/router/conversion, the complete GH5 oracle
matrix, bilateral and unilateral recovery, fresh randomness, cold replay,
invalidity/high-alias rejection, g8/g18, signed caps, source/stage tamper and
actual spool workers. A new C65 fixture exercises repeated full chunks and
tails through the encrypted durable graph. Original and updated public graph
fingerprints match for both small and n2000 shapes. All four packaged runtimes
were rebuilt and checksummed against the proved native source.

Raw native proof, source hashes, compilation measurements and independent
review are in the workspace's `integrator-evidence/cycle12-20260920/`.
These component results do not establish signed n2000 capacity or promotion.
The cycle10 LMM and cycle11 binomial n2000 drivers retain their frozen source
identities. A fresh signed smoke must validate these rebuilt runtimes; old
release results must not be relabeled as measurements of this revision.

---

# Cycle 11 authenticated binomial GH5 stage graph — 2026-09-20

The binomial variance-grid producer is now connected to the shared authenticated
source/router/conversion, durable PREPARE/COMMIT executor and sticky exact-GC
Synopsis lifecycle. It retains the certified GH5 tables and exact OT products;
this is finite quadrature-grid selection, not an adaptive GLMM fit. The new
composition certificate is documented in NUMERIC_CERTIFICATE_BINOMIAL_GLMM_GH5.md.

Binary outcomes enter a separate authenticated q0 stage, are checked at full
Ring128 width, then normalized for the existing f50 private router. A single
route and corrected private-carry conversion feed guarded q0 live/outcome/count
and complete f100 predictors. Durable typed stages perform node softplus,
private live/profile and y/eta products, cluster scores, private maximum,
negative exponential and full-width guarded logsum, signed cluster caps and
candidate sums. Private source and arithmetic validity reaches the DP sampler;
no source, routing, count, carry, maximum or validity bit is released.

The new signed variance grid is an ordered unique subset of {0,1/4}, with
variance-major/beta-minor candidates. Its complete-vector caps and patient
sensitivities are recomputed on both sides. The new producer admits p<=3 and
J<=4; n2000/C500/B4/p3/J4 has an explicit measurement-only domain. Encoded f50
predictor endpoints are checked before source production. Existing fixed-grid
reference contracts and LMM ML contract bytes are preserved.

Internal helpers retaining the LMM name now dispatch only the two authenticated
typed producers. GLMM uses separate operation, store, session, source, receipt
and terminal record domains. The public binomial reader verifies both authority
signatures and published provenance, including a cold exported-API path. Other
structured readers remain closed. The existing internal cross_lmm_evidence
container carries the family-specific staged receipts; it is not a claim that
GLMM uses the LMM objective.

Pod4 focused server/client checks pass 536/410 assertions (including the real R-to-Go handoff and
fresh alignment source-byte stability). The native complete
source and GH5 graph passes independent integer-oracle, both durable recovery
branches, cold replay and invalid-input checks. Full signed release, n2000
K2/K3/K5, final source/stage tamper and capacity/paired-suite proofs remain
under validation. No promotion or measured GLMM capacity is claimed here.
Evidence and exact frozen source identities are in the workspace's
integrator-evidence/cycle11-20260920 directory. The governing ceiling is
256 GB / 6 hours; the older preflight limit below is historical.

---

# GH5 share composition integration

`registerGroupedGLMMLoss().Shares` exposes PredictorCompile, ScalarCompile,
ScoreShares, CenterCompile and FinalCompile. The original `.Compile` is the
whole-cluster prototype and must not be scheduled as the clause-5 architecture.

Required traversal after ONE authenticated primitive grouping of packed rows:
1. Form complete f100 eta on shares and run PredictorCompile with bound=1.
   It implements the frozen f100 -> q64 -> q16 sequence with private guards.
   Add each public GH node to one authority's eta share, then ScalarCompile
   evaluates softplus or range-reduced exp, with Ring192 masked outputs.
   Carry predictor validity: scalar inputs must already be certified int32
   values; the bridge's modular narrowing cannot validate high input bits.
2. The exact OT component computes live*profile once per (row,node,candidate)
   and y*eta once per (row,candidate), reused at all five nodes. Thus GH5 needs
   six private products per row/candidate for these terms, plus any missing
   source/validity preprocessing. Do not describe all quadrature composition
   as product-free. Public node*y is a local multiplication of shares.
   Supply privately validated, masked y and log(y!) shares (y<=4).
3. ScoreShares accumulates all node scores locally. CenterCompile yields five
   shared clipped exp arguments, the shared maximum and private validity.
   ScalarCompile(exp_negative) yields GH terms; sum on shares, then
   ScalarCompile(log). The integer exp at -16 is zero, preserving the prior
   truncation rule. No count or maximum may be opened.
4. FinalCompile accepts the exact signed candidate cap U_j, rather than forcing
   the prototype's universal bound. It consumes maximum, log sum, private count
   and ALL prior validity. It clamps/rounds once; empty clusters return zero.
5. Bind source/primitive/chunk receipts, joint DP noise, sticky accounting and
   output evidence through Step 2. Add process-isolated protected DSLite tests
   and the full capacity matrix before enabling R materializer/client reader.

The decomposition preserves the existing integer GH5 oracle and certificate;
binomial/Poisson, both admitted variances, partial/empty clusters, rejection
and cap tests pass. Scalar outputs remain Ring192 shares, avoiding unsafe local
widening. Exp uses <5000 AND/value including masks; see Addendum-3 measurements.
No full-release envelope or authenticated R release is claimed.

## Addendum 4 preflight — 2026-09-18

The binding ceiling is **110 GB / 4 h**. No release capacity is admitted;
all requested shapes are rejected by current prototype contracts. See
INTEGRATION_GROUPED.md's Addendum 4 section and
`inst/grouped-validation/addendum4-preflight.json` for the unmeasured matrix
and exact prerequisites. Component timings do not establish release capacity.
