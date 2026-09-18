# Step 2 decisions

## 2026-09-18T12:45Z — resumed

1. Preserve the committed V1 profile, references and signatures. The arithmetic
   addendum supersedes its nonlinear arithmetic, not its source f50 encoding,
   ownership, alignment, complete-case semantics or release authorization.
   A replacement profile requires its own identity, hash and error certificate;
   old signed q64 contracts must never silently select new arithmetic.
2. Measure a new Boolean-engine piecewise profile before integrating release.
   The existing ring/spline implementation is not a drop-in certified backend:
   its binomial/Poisson domains are hardcoded, its tail rules differ, and its
   coefficient generation uses ordinary floating point. Its trusted combined
   preprocessing helpers do not establish two-authority production security.
   No sealed generation-one route will be reopened.
3. Preserve all baseline files. Newly generated numerical fixtures contain only
   public coefficients and synthetic inputs. A profile cost experiment is not
   a completed kernel, release, or whole-workload benchmark.

## 2026-09-18T13:02Z — candidate profile and measured cost

4. Evaluate quadratic interpolation at interval endpoints and midpoint, K in
   {16,32,64}, signed public envelope A in {1,2,4,8,16}. Use f16 nonlinear words
   except full-domain Poisson f6; exp(16) cannot fit a 32-bit f16 word. Retain
   exact 64-bit raw products and nearest-even rounding. This is a proposed new
   arithmetic identity, never a reinterpretation of a signed V1 contract.
5. An initial f26 binomial / larger-fraction Poisson probe was too costly.
   Regenerate the certificate for the lower precision before measuring it.
   Keep the final reproducible variants, not obsolete coefficient files.
6. The compiler's default wide multiplication and unreduced constant-table
   logic overestimate the useful Boolean circuit. A test-only Boolean
   constant-folding/shared-expression pass and the existing array-multiplier
   option provide a smaller exactly equivalent circuit. Exhaustive 8-bit
   comparison and all profile boundary/random comparisons pass. No shared
   production engine code, compiler defaults or sealed family route changed.
7. Gate counts include input-share reconstruction, range handling and output
   masking in this component probe. Count a 128-bit garbled label as 16 bytes;
   exactGCGarbledRowSize returns labels, not bytes. Report actual encrypted
   protocol traffic separately from garbled-table payload and extrapolations.
8. Do not promote this candidate: the optimized K=64 circuits still exceed
   2,000 AND gates/evaluation, and full-domain Poisson utility is not certified
   relative to production noise. Batching amortizes OT/framing but cannot
   eliminate per-evaluation table payload. A new arithmetic design remains
   necessary; benchmark projections are not completed grid runs.
9. No DESCRIPTION/NEWS/roxygen changes are warranted for test-only experiments.
   No exported or internal production R function changes, no client changes,
   and no new materialized-state claim are made. The three evidence files
   explicitly distinguish completed component tests from unexecuted gates.

## 2026-09-18T13:12Z — resumed; binding revised cost gate

10. Addendum 3 supersedes decision 8's numerical cost thresholds: <=5000
    AND/evaluation and <=60 GB measured two-direction whole-release traffic.
    Retain the certified binomial candidate; do not optimize below that gate.
    Component table bytes alone do not establish the whole-release gate.
11. Replace full-domain Poisson interpolation with fixed-point range reduction
    and a short piecewise polynomial for the reduced exponential. Certify
    reduction, polynomial, rounding and power-of-two reconstruction separately.
    New arithmetic remains unadmitted until its signed identity and production
    lifecycle are implemented; never reinterpret existing signed q64 contracts.

12. Certify eta26, ln2/reciprocal f30, reduced residual f24 and quadratic
    mantissas f27, with K in {16,32,64} on [-1/2,1/2]. The shared source f50
    encoding remains fixed. Use exact uint64 multiplication temporaries;
    polynomial states fit signed32. Full-domain f16 output requires 40 bits
    and a uint64 container. Narrow the residual subtraction only after proving
    its signed30 bound. A six-stage guard/sticky barrel shifter rounds once.
13. K=64 is both the cheapest measured range-reduced candidate (3540 AND,
    versus 3546/3643 for K32/K16) and the most accurate. Select it for further
    integration. Its pre-output loss bound is 3.17234243e-5 at A4 and 1.43799821
    at A16. The R utility assertion is explicitly scoped to A4, 16 equal-cap
    candidates, n2000 and epsilon<=8; arbitrary production grids still need
    the admitted public utility/resource plan checks.
14. Add opt-in fixed-topology framing to the existing exact-GC protocol core.
    The old entry functions always select the old mode, preserving their
    context digest and every transmitted row-length word. The new mode omits
    per-gate row lengths only after both peers authenticate a domain-separated
    digest committing all gate operations/wires and input/output geometry.
    This saves ~49 KB/evaluation for Poisson without changing arithmetic,
    garbling, KOS OT, encryption or DP parameters. No production dispatcher
    selects it yet. This is the sole changed shared infrastructure; other
    family lanes can adopt it only with their own bound public plans.
15. Batch 32 nonlinear evaluations for component measurements; report total
    bidirectional encrypted bytes including fresh OT/setup. Binomial retains
    its certified K64 polynomial and uses the same uint64 masked-output test
    container for comparable framing. Its ~33 extra ANDs are container work.
    Component projection is not a measured full-size release or evidence that
    the full source/validity/loss/noise computation fits 60 GB or 30 minutes.
16. Validate pooled synthetic objectives in Layer 1 now: n2000, p6 split3/3,
    dyadic known coefficients, 16 nearby candidates plus glm's fitted vector.
    Poisson outcomes are bounded at 4 before fitting, consistent with the
    signed bounded-outcome semantics. Compare the same bounded data with
    independent R distributions and glm logLik, never label this a DSLite run.
17. Keep the revised full-release cost gate OPEN. Compact batch32 component
    traffic projects to 47.018/51.374 GB for binomial A4/A16 and 58.785 GB for
    Poisson at 500000 evaluations. That is not sufficient headroom evidence
    for the remaining source, loss and DP work. Pod measured component latency
    is 20.854/33.419/28.204 ms per evaluation; do not label serial extrapolation
    a measured whole-release result, or silently reduce the signed workload.
18. No version bump, NEWS or production roxygen changes: no R API, client route
    or materialized-state claim was introduced. Evidence documentation covers
    the new candidate and opt-in internal framing only. Production documentation
    remains part of the unfinished release deliverable. No BLOCKED_V2 file is
    warranted: the outstanding work is implementation, not a missing decision.

## 2026-09-18T13:43Z — fused producer integration

19. Form exact public-coefficient f100 partial predictors locally on Ring128
shares, with the intercept on the garbler share only. Reconstruct and validate
the original source records privately in the fused circuit; invalid rows zero
their predictor before nonlinear evaluation. This avoids secret circuit
multiplication by public coefficients without independently rounding owners.
The producer, not an RPC caller, derives these partial predictors.

## 2026-09-18T14:17Z — fused integer and protocol decisions

20. Move the accepted profile code and optimizer from test files into internal
    Go implementation files without changing coefficients, identities or
    evaluation order. Pin a reproducible embedded table bundle including the
    interval-rounded f16 log-factorials. Keep independent big.Int/R oracles.
21. Use floor plus the nonnegative remainder for signed nearest-even rounding;
    this avoids a wide absolute-value circuit and preserves negative ties.
    Narrow eta and binomial loss only within proven signed32 bounds; accumulate
    clamped candidate integers in uint64 under the existing 2^53-1 limit.
22. Add an isolated internal session operation to the exact-GC validator and
    explicitly reject it in the ordinary compiler. Its specialized runner
    binds public plan and compact topology, keeps alignment validity private
    and returns full Ring128 masks. This is not an R allowlist expansion,
    authenticated source binding or durable release authorization.
23. Test actual kernel-to-joint-vector-Laplace composition over net.Pipe at
    epsilon=4 and delta=2^-100, including the sampler's output clamp. Do not
    represent it as a DataSHIELD release, lifecycle test, or selection-statistic
    licensing gate. Server policy/seed/sticky bindings are still absent.
24. The first fused benchmark used oversized stress caps; preserve those logs
    as exploratory. Final cost evidence uses the certified A4 caps and distinct
    exact-L1=4 candidates. Aggregate full-release traffic must not be inferred
    to pass from the nonlinear component alone. Source validation, Ring128
    transport, rounding, loss assembly and sum masks also cost gates/bytes.
25. No version/NEWS/roxygen change: the new primitive is internal and unadmitted.
    The required production API documentation remains unfinished.

## 2026-09-18T14:28Z — failed complete-kernel resource gate

26. Use the certified-cap measurements, not the exploratory stress-cap run,
    for the gate verdict. The full frozen workload has 1872 complete 32x8
    batches. At 32 table bytes/AND, their payload alone is 64.481564160 GB
    (binomial) / 83.829118464 GB (Poisson), before all omitted work. The
    current complete route therefore cannot satisfy the binding 60-GB gate.
27. Do not spend a full-size protected-path run to relabel a deterministic
    payload lower bound as a measured release. No full n2000/n10000 runtime
    is claimed; the full benchmark deliverable stays NOT DONE. Batch-byte
    and serial-time extrapolations are labelled projections only.
28. Record the failed resource gate in BLOCKED_V2 for reviewer disposition.
    No resource limit, candidate grid, source ABI, profile, privacy default,
    production allowlist or materialized-state declaration is weakened. A
    replacement computation design remains possible but unimplemented; this
    is not an impossibility claim about all MPC designs.

## 2026-09-18T14:46:35+00:00 — reviewer-resolved resource gate

29. Addendum 5 and gate-revision clause 6 supersede decisions 26–28 as a
    stopping condition. Preserve the certified arithmetic and full workload.
    Run bounded concurrent peer pairs, aggregate actual encrypted bytes and
    candidate-sum shares, then run the existing joint-noise circuit. Record
    kernel/noise computation separately from authenticated R/DataSHIELD release:
    the latter remains unfinished and cannot be claimed by a Go benchmark.

30. New-profile contracts explicitly select `piecewise_v2`; the default V1
    builder and old signatures retain q64 arithmetic. Reconstruction detects
    the pinned numeric identity and recomputes every field before verifying
    signatures. Production profile admission additionally rejects V1 arithmetic.
31. Pin a compact outward-interval cap certificate for all five power-of-two
    eta envelopes and every Poisson M=1..1024. Select the smallest common
    envelope enclosing all signed candidate L1 norms using the V1 exact
    expansion comparator. This deliberately uses conservative equal envelope
    caps, rather than unproved runtime libm maxima. For g<=18,
    ceil(U18/2^(18-g)) equals ceil(2^g*(L+2E)); integer clamp proves sensitivity.
    Common envelopes may increase noise for heterogeneous grids; document this
    limit. Features, f100 predictor, row/candidate traversal and output g remain
    unchanged. The new certificate and profile hashes are signed on both sides.

32. Extend the existing private exact-GC worker config with an optional typed
    grid plan, accepted only for the new operation and its exact plan purpose.
    Ordinary compiler/R staging remain closed until authenticated source binding
    is implemented. Existing worker operations reject unexpected grid metadata.
33. Durable-spool testing exposed a missing connection-finalization call in the
    internal fused runner: net.Pipe hid an asynchronous final-ack flush race.
    Use the existing exactGCFinishConn drain/flush before returning outputs.
    No polynomial, output value, gate, or protocol message changes. The running
    net.Pipe cost snapshot predates this lifecycle fix and is identified as such.

34. The pod exposes 96 CPUs but its cgroup CPU quota is 765000/100000,
    i.e. 7.65 cores. Use GOMAXPROCS=8 and four concurrent two-peer pairs.
    The first n2000 attempt was interrupted during compilation, before any
    n10000 execution. Cache benchmark circuits only by the SHA256 of identical
    generated source; each candidate batch keeps its own immutable coefficient
    plan, predictor packer and purpose. This removes duplicate compilation,
    not gates/evaluations. A 17-candidate smoke test exercises cache reuse and
    tails, with complete integer/DP equality for both families.

35. Derive the garbler's batch output masks from a private custodian HMAC of
    the semantic release key and public batch index. Keep the transport session
    and source-sharing randomness fresh on retry. This makes separately durable
    peer outputs compatible after crashes without exposing masks/seeds. New
    worker tests reproduce both shares across fresh transport and source shares.
36. Use the vector sampler's admitted MaximumChunkCoordinates for the joint
    noise phase, with one global-vector sensitivity/delta calibration and global
    coordinate offsets. The first n2000 source/loss computation completed but
    its unchunked 50-coordinate noise request failed the existing type limit.
    This is a harness bug, not a changed privacy/circuit cap. No n10000 run had
    begun. A 50-coordinate Mac smoke now passes both complete mechanisms; run
    n10000 first on the next pod launch, then n2000.

## 2026-09-18T15:44Z — authenticated grid materialisation and public bootstrap

- Reuse the existing private PSI alignment-mask transport, capsule coordinate layout, two computation roles and joint sampler. Only the two new grid versions add source blocks (f50 predictors; f0 integer outcomes/validities) and initially-zero release coordinates. Other family arithmetic is unchanged.
- The signed contract is a canonical JSON scalar in workload descriptors/fragments. This preserves its exact signature message and avoids weakening the generic capsule ban on executable-looking nested `method`/`operation` fields. The workload wrapper calls the public producer name `producer`; the embedded original contract is unchanged.
- New-version-only snapshot normalization hashes the complete public spec except the three schema-derived fields: schema hash, logical snapshot, and alignment-contract hash. This breaks the otherwise circular schema→workload→signed-schema dependency. Unanimous schema/contract signatures and the full workload hash still bind the excluded derived fields. Custodian references are never rewritten. Existing family snapshot calculations are byte-for-byte unchanged.
- Source result records are MAC-authenticated and bind capsule, analysis, batch, semantic key and plan. Final injection adds to a freshly loaded original aggregate and never persists an injected aggregate. Stable private HMAC output masks make recomputation across sessions compatible with immutable persisted records. The semantic key includes full signed contract, profile/caps, mechanism and source contract; the Synopsis source contract binds authenticated source claims/alignment.
- The new exported aggregate authenticates the existing Synopsis compilation before bind/prepare/store/finalize. The generic exact worker accepts the special plan only from this internally staged producer, never from generic user source staging.
- Client certificate reuse: the existing two-authority signed Synopsis publication and authenticated source-contract binding prove the grid release route; grid validation additionally rechecks both custodians' complete signed arithmetic contract against the signed schema. The Gaussian-specific supplemental evidence rule remains unchanged for Gaussian models.
- Client syntax permits additive `owner$column` references. Signature/cap validation and formula matching run after public catalog bootstrap but before any protected source claim or release. A previously unknown server-owned catalog cannot be validated before fetching its public metadata. No inference/standard errors are added.

## 2026-09-18T16:08Z — DSLite wiring corrections

- Preserve the actual signed PSI protocol version in the synthetic custodian bootstrap (currently 4), instead of the harness's initial hard-coded 1. No production alignment or signature check was weakened.
- The Synopsis source-manifest adapter must recognize grid-private source geometry/purpose, in addition to its existing Gaussian/categorical branches.
- A dedicated grid computation session receives the existing authenticated Synopsis PREPARE before exact transport setup. This supplies the authoritative artifact binding required by the pinned-peer handshake; generic unauthenticated setup is not used.
- Register the new lifecycle method in the client's existing idempotent-call and JSON text-framing maps. Its large public compilation/claim arguments need the same DSLite-safe framing as existing cross-owner methods. No generic parser or admission exception was added.
- No maintainer file requires a version/NEWS bump for this branch; versions and NEWS remain unchanged. Roxygen generated the changed GLM help section; unrelated pre-existing regeneration drift was discarded.

## 2026-09-18T16:26Z — typed worker wiring

The authenticated grid endpoint adds `start` rather than permitting generic client staging. State keys retain the exact worker namespace. Capsule-source transport uses URL-safe base64, but exact worker inputs/results use canonical standard base64; conversion occurs only at the internal typed producer boundary, with no relaxed decoder. The synthetic oracle wiring assertion compares the full authenticated decimal-integer replay vector before any conversion to doubles.

## 2026-09-18T16:36Z — grid-scoped joint-noise admission

The first completed synthetic DSLite release exposed a legacy sampler selection: generation one promotes exact joint noise only for dimension 1; a candidate vector therefore selected convolution. That completed run does **not** satisfy the requested release gate. Add a distinct `dsvert-cross-grid-exact-gc-cost-policy-v2`, selected only from the new signed family catalog, admitting at most 51 coordinates (50 candidates plus canonical count). The legacy policy and its one-coordinate ceiling remain unchanged. Physical-plan validation recomputes the policy from the authenticated manifest; assessment/binding validators understand the explicit policy version. Noise chunks use the global calibrated plan and its certified maximum chunk capacity, with client START traversal matching that private execution geometry. No epsilon, delta, source encoding, or clipping cap changes.

The independent oracle rejected extra release coordinates, revealing automatic numeric-moment expansion from the new grid's source references. New `glm_grid_cross` descriptors now validate source-column resolution without adding those moments to the public catalog; their typed private source blocks supply the kernel. Explicitly configured primitives and all older families retain their prior behavior. The synthetic fixture is intentionally a count-plus-grid catalog.

For validation, use the existing 8 MiB maximum exact-transport chunk setting (no raised cap) to amortize DSLite framing. Synthetic private state remains under ignored/R-build-excluded directories. Launch R harnesses via `source()` so a later development edit cannot alter the script tail being interpreted. Claim collection explicitly includes every grid source owner, including owners that have no public primitive block.

Transport tuning correction: the worker allows 8 MiB, but that exceeds the existing client negotiated expression ceiling (768 KiB minus one byte). The experimental setting was rejected before PSI completion and removed; retain the default 480 KiB chunks. No expression/resource ceiling is raised.

The new route must never silently select a non-MPC noise fallback. Its scoped admission therefore requires the certified discrete-Laplace mechanism; a catalog choosing another mechanism is rejected on both server and client. The required epsilon 1/4/8, delta=2^-100 matrix selects Laplace unchanged. Older Gaussian/convolution routes and their defaults remain unchanged; extending this new route to other mechanisms is not implicitly promoted.

## 2026-09-18T17:33Z — pod private validation state

The RunPod workspace filesystem cannot enforce the private-directory mode required by identity provisioning (requested 0700, observed 0777). Keep all production permission checks. The synthetic harness accepts `DSVERT_GRID_VALIDATION_STATE_PARENT`; the pod runner uses local `/tmp/dsvert-crossowner-v2-state` (verified 0700). This holds only ephemeral identities, shares, synthetic oracle inputs and stores, removed by the harness on exit. Source and public evidence remain under `/workspace/dsvert/crossowner-v2`. No production path or arithmetic ABI changes.

## 2026-09-18T17:35Z — private state location corrected; topology campaign

The `/tmp` attempt also failed before release: production noise roots explicitly reject temporary trees. The final synthetic state parent is `/var/lib/dsvert-crossowner-v2-validation`, verified root-owned mode 0700. No permission/noise-root validation is bypassed. Matrix restart PID **450578**.

Additional clause-7 topology campaign uses the same hash-frozen harness and two compute/noise authorities: per family K3 at **n10000/p10/grid50**, and K5 at the explicitly smaller **n2000/p6/grid2**, epsilon4. Each release requires real multi-owner PSI, all signatures, full integer DP-vector oracle equality, DP selection equality and fresh-process record checks. Runner: `inst/cross-grid-v2/run_topology_validation_pod.sh`. These four releases are additional to, and not counted in, the 120/12 matrix.

## 2026-09-18T17:39Z — documentation and check freeze

Added matching package documentation for source ownership/signatures, PSI, certified arithmetic, scoped Laplace sampler, sticky lifecycle, states and finite-grid DP-best interpretation. Client roxygen and generated Rd describe the same route. No repository maintainer instruction requires a version/NEWS change for this development branch, so both versions remain 1.2.0 and NEWS is unchanged. Full checks use a dedicated frozen source archive; subsequent evidence files do not change runtime code.

## 2026-09-18T17:47Z — serialized pod validation after memory exhaustion

Concurrent large PSI setups reached the actual 50,000,000,000-byte cgroup memory ceiling (observed peak 50,000,023,552; fail counter 11). Binomial's R process segfaulted during polling; the other lanes failed closed during PSI transport. No alignment/release completed. A surviving worker held approximately 33 GB RSS, then exited before cleanup. Failure logs are retained on the pod in `logs/failed-concurrent-psi/`.

Restarted the matrix sequentially by family under `GOMEMLIMIT=6GiB`, `GOGC=25`, two Go scheduler threads per worker (PID **458353**). The topology runner (PID **458354**) waits for successful completion of that matrix and also runs families sequentially. These are runtime scheduling/GC controls only; no circuit, capacity, transcript, privacy or admission limit changes. The remaining raw benchmark matrix still runs with its previously frozen settings.

## 2026-09-18T17:54Z — preserve completed benchmark evidence

A benchmark process interruption does not erase earlier completed family measurements. Resume only missing family/configuration pairs; retain original logs and label interrupted processes. FULL_MEASUREMENT is emitted only after integer and joint-noise equality assertions. The report additionally rejects explicit failed tests and verifies the full-envelope byte/time ceilings. Resumed measurements explicitly record different Go GC resource settings; the two original full-envelope results are unchanged.
