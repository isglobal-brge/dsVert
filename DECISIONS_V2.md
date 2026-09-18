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

## 2026-09-18T17:59Z — required shared PSI compiler infrastructure

The serialized n2000 PSI comparison still exhausted pod memory (cgroup fail count rose from 11 to 14); both peer workers exceeded roughly 19–20 GB RSS before failing closed. The existing generic compare source branches on assignments to an entire output array inside its loop. Changed only its source form to a scalar conditional followed by one array assignment. The signed comparison, masking, wire types, threshold, output shape, operation identity, PSI contract/chunk sizes and sealed route admission are unchanged. This shared infrastructure change is necessary to exercise the requested existing PSI path at capacity; it is not a new arithmetic profile or relaxed gate.

Targeted tests compare the exact old array-branch source with the new source for nine width/threshold combinations and 20 random masked vectors each, plus existing independent big-integer and two-peer protocol tests. All pass in 0.673 s. Public capacity compilation at 2048/4096 is being measured before deployment; no capacity success is asserted yet.

## 2026-09-18T18:04Z — PSI chunk size obeys the existing worker cap

The scalar source compiles n2048 in 52.009 s (3,002,371 gates) on the pod. The former n4096 PSI chunk is rejected by the unchanged 524,288 typed-input-bit cap: three uint64 arrays need 786,432 bits. Lowered only the public PSI AND chunk capacity to 2048 on server and client. Chunk operation IDs already bind index and count; membership reconstruction and cleanup use the same constant. Small existing capacities (<=2048) retain their schedule; larger buckets use more chunks with identical membership semantics. No cryptographic/worker cap, privacy parameter, signed source binding or cross-grid ABI is relaxed. This shared PSI correction is required by the K3 full-envelope wiring gate and available to other family lanes.

Targeted schedule tests: server 6 assertions and client 19 assertions, zero failures/errors. Server covers the full 16384 bucket without gaps/overlaps and distinct chunk IDs; client exercises 64 and 8192 buckets. The four packaged binaries were rebuilt after the scalar compiler change.

## 2026-09-18T18:22Z — use idle Mac for independent topology evidence

The required two-peer matrix remains on the pod; additional K3/K5 API topology checks move to the Mac after its complete benchmark matrix. These checks have no pod-only requirement, whereas full package suites still run on the pod. This avoids waiting for sequential topology runs on the CPU/memory-constrained shared pod and does not duplicate completed releases. Existing full-size pod cost evidence remains explicitly the raw Go kernel/noise measurement.

## 2026-09-18T18:30Z — retain DSLite private storage IDs in the PSI relay

The first K3 n10000 attempt failed before alignment, at the first large-envelope reference export. The existing relay demanded equality between the protocol UUID and `.S()`'s internally suffixed DSLite disk ID. Added a server-owned `.public_session_id` when creating `.S()` state; relay admission validates that public UUID and permits only the exact matching UUID plus the existing hashed DSLite suffix as its private storage ID. The private ID/path is never rewritten. Legacy nonsuffixed sessions and all cryptographic header/session bindings retain their behavior. Mismatched public and private UUIDs still reject. This is a second required shared PSI/DSLite infrastructure correction, not a family-specific bypass.

A regression reproduces the original mismatch; after the fix, relay/session/security tests have **582 passing assertions**. The initial regression cleanup used the wrong deferred-cleanup ordering; corrected the test to close its own relay before restoring its temporary root, removing its transient resource-accounting interference. No resource cap was changed. The K2 n2000 pod path stays on its frozen b542b84 runtime because it uses inline PSI envelopes; the new relay path is validated separately by K3 and by full checks.

## 2026-09-18T18:34Z — bound large PSI membership sharing without raising caps

K3 passed the large-envelope relay after the UUID fix, then failed at private membership sharing: target matching passed the entire 16384-slot bucket to a Ring63 bit helper capped at 4096. The purpose-bound membership caller now shares fixed 2048-coordinate chunks and concatenates canonical Ring63 records. The existing bit-helper cap remains unchanged; small buckets produce exactly the same bytes under the same entropy. Full wire shape, encrypted-envelope context, signed capacity and membership semantics are unchanged.

Pure-R tests reconstruct all 16384 bits exactly, verify bounded entropy requests, reject wrong shapes/invalid bits, retain the old helper's oversized-vector rejection, and compare the small-bucket wire output with the original path. **89 assertions pass** across chunk/canonical Ring63 tests (`psi-membership-targeted.log`). This required shared PSI correction is recorded for other family lanes. The failed K3 attempt released no DP vector and remains `topology-binomial-k3-before-membership.log`.

## 2026-09-18T18:58Z — scoped fused-grid alignment projection

A grid-only private source layout now selects `fused-grid-digest-v3`: the existing bilateral all-owner XOR-digest circuit checks alignment and masks one hidden coordinate. The completed authenticated terminal remains mandatory before any source read. Only the exact admitted typed-grid artifact may then read MAC-authenticated aggregate source shares; its fused circuit independently guards every row using the same private digests. Missing/invalid terminals, changed artifacts and altered projection geometry fail before reads. The projection is derived from the signed contiguous layout, never caller-selected. Mixed/older-family layouts retain their existing full/private-suffix mask routes. Grid-only layouts expose exactly one projection to avoid ambiguous one-chunk operation IDs. No arithmetic ABI, noise, sensitivity cap or public invalid-alignment behavior changes.

This shared-infrastructure specialization removes redundant masking of every private coordinate before the fused kernel repeats the guard. It was prompted by the n2000 campaign's long generic alignment prepass. The interrupted prepass produced no qualifying release; its log is retained on the pod. Server 376 and client 375 targeted assertions pass, including fail-before-read checks and mixed-family projection regression.

## 2026-09-18T19:07Z — session compatibility and public topology fixture

The earlier relay correction's extra `.public_session_id` environment binding conflicted with Synopsis's closed authorization-state allowlist. Removed that binding; the relay now checks the public UUID against either the exact private ID or its exact `UUID__dslite_<16 hex>` form. It never changes the private storage ID. The regression now checks authorization admission before relay initialization, plus mismatched UUID rejection. No authorization allowlist was widened.

The pre-existing peer-relay inventory omitted Gaussian Synopsis endpoints and separately sealed formal GLM/Cox registrations. Added the new grid and existing Gaussian endpoints to Synopsis coverage. Explicitly inventory the formal registrations as a separate, **not covered** profile rather than asserting this task certifies them. The registration-coverage test retains all existing active-channel security assertions and checks that separate-profile status. No formal-family implementation changed.

Large topology fixture failure was public canonical predictor order: `x10` sorts before `x8`, while the fixture used numerical order. Ten-predictor synthetic fixtures now use `x01`–`x10` and assert radix order before starting any peer. Six-predictor campaign inputs are unchanged. This is a harness correction, not relaxed admission or a changed ABI.

Package build exclusions retain the immutable runtime admission certificate but exclude development benchmark/validation outputs and root V1/V2 reports. Reports remain in git; private temporary build state was already ignored and excluded. Versions and NEWS remain unchanged.

## 2026-09-18T19:14Z — bounded typed-worker readiness window

The first n2000 typed-kernel START failed before worker readiness; the pod memory-failure counter remained 14. The typed Go worker compiles its admitted public circuit before setting the ready marker (and before decoding source residues), whereas the generic R launcher waits only 100 × 50 ms. Larger certified batches can exceed that five-second window. Scope a 120-second startup wait to `glm-grid-profile-v2` only; keep the five-second window for every existing operation. Worker inactivity/maximum-runtime leases, context derivation, retry attempt, protocol, arithmetic and caps are unchanged. No Go binary rebuild is needed. Existing K2/K3/K5 readiness/attempt and policy-pair tests pass 60 assertions. The restarted n2000 API campaign is the actual larger-batch regression gate; it is not yet claimed complete.

## 2026-09-18T19:35Z — reuse immutable admission only within the bound grid session

The new grid endpoint previously rebuilt and reverified the entire signed source compilation on every prepare/start/store call. It now performs that full validation at bind, then keeps the validated public request tuple and private policy context in the existing server-owned grid binding. Every later stage requires identical manifest-selector, Claim-set JSON and compilation JSON, the same analysis/session, the same peer-binding digest, and matching artifact/source-contract hashes. There is no caller-provided cache token and no cross-session cache. A fresh process/session must authenticate bind again. Durable batch reads/writes retain their MAC and semantic-key checks; final joint-noise/publication authorization is unchanged. Full source validation also remains on repeated bind calls.

This removes repeated work on immutable public contracts, not a protected computation or validation of newly supplied data. The byte-identity regression rejects missing admission, changed claims/compilation/manifest, another analysis, changed artifact and changed peer binding before a later-stage handler can execute. Targeted grid contract/lifecycle file: 292 assertions pass. Actual throughput improvement remains to be measured by the required API runs; no speedup is assumed in the reports.

## 2026-09-18T20:11Z — authenticated public-circuit reuse and existing relay window

Observed pod typed-worker startup was 22.9–24.0 seconds per batch, followed by substantial relay time. Recompiling the same public topology for each of 63 or 2191 batches is unnecessary. The existing compiler's binary circuit format now supports a **session-local, HMAC-authenticated public topology cache**. Its key binds the complete generated source and pinned compiler/optimizer domain. Cached bytes contain no source shares, candidate-specific partial predictors, output masks or DP seeds. Coefficients remain in each admitted plan and its signed purpose; they affect private share multiplication, not cached topology. The cache directory is server-derived under the private session directory and removed by ordinary session cleanup. Files are owner-only, atomically installed, bounded in size, and authenticated before parsing; altered MAC/key/content, truncation, symlinks and unsafe permissions fail closed with the constant kernel error. This reuses the existing compiler Marshal/ParseMPCLC functions and POSIX directory-owner check; no formal-family implementation changes.

The private unlink-before-ready worker configuration gains an optional `cross_grid_cache` field. Non-grid operations reject a non-null cache policy. The public source/producer ABI, signed profile identities, chunk geometry, arithmetic, noise mechanism, gate counts and peer protocol are unchanged. There is no fallback from a corrupt supplied cache to unauthenticated data. Existing raw benchmark measurements remain on their original frozen snapshot; cached/uncached circuit bytes and actual net.Pipe oracle results are identical.

Validation peers now select the already-supported **8 MiB** exact-GC relay window instead of the 480 KiB default. Both client and server already enforce the 16 KiB–8 MiB range and bind the selected window in initialization. No transport cap or privacy default is increased. This is a harness deployment setting, not an arithmetic ABI change. GOMEMLIMIT/GOGC limits remain as previously documented.

Tests: authenticated cold/hot cache, byte-identical topology after changed public coefficients, real two-peer oracle equality, tamper/authority/path rejection; durable CLI workers for both families; unchanged two-authority valid/invalid records and malformed-plan rejection (10 Go test/subtest results, all pass). R grid/lifecycle plus existing pair/readiness tests: **352 assertions pass**. Small-fixture warm loads are 0.005–0.008 seconds versus 0.25–0.42 seconds cold; no full-release speedup is extrapolated. Go 1.25.7 `make all` reproduces all four binary hashes on Mac and pod.

## 2026-09-18T20:16Z — relay correction

The 8 MiB experiment above was rejected by the fixed negotiated expression policy before admission. Restore the existing 480 KiB default, as already established earlier in this log. Keep the authenticated public-circuit cache; do not alter expression caps.

## 2026-09-18T20:28Z — remote inventory completeness

The full server suite exposed a missing documentation inventory entry for the new registered `dsvertDPSynopsisGLMGridCrossDS` endpoint. Add it to the existing purpose-bound classification and update the registered count from 96 to 97. No endpoint registration or test assertion changes. The running frozen check keeps its original files; its failure is retained, then the corrected package must be checked again.

## 2026-09-18T20:30Z — derive check archive versions

The runner incorrectly assumed both existing package versions were 1.2.0. Server is 1.2.0 and client is 1.2.1. Derive tarball names from each DESCRIPTION; no version or NEWS change. The already-built client archive is checked independently (PID739243) while the server suite continues, because its known inventory failure will stop the original sequential runner.

## 2026-09-18T20:36Z — check-layout-compatible test fixtures

The full server check exposed two source-root assumptions in tests: the Count static audit used `../../R`, and the grid callr test treated the Rcheck directory as a package source root. Use the existing source-tree discovery helpers for both. The Gaussian binding mock returned its assignment vector rather than the completion record returned by the actual alignment gate; return the legacy `full-v1` record after recording the assertion data. No production behavior changes. Pod reproduction confirms all three original errors; local targeted rerun passes 137 Count + 39 Gaussian + 292 grid assertions.

## 2026-09-18T20:40Z — isolated Synopsis test dependencies

Nested Synopsis fixtures evaluate vector-helper definitions in a namespace-parented environment. Under installed checks that environment cannot resolve the shared source-root helper. Load `helper-source-tree.R` explicitly inside the private vector-binary fixture closure; production namespaces remain untouched. The execution-range test intentionally replaces manifests with a stub and mocks injection stages; add the new grid injection mock and its offset/count assertion alongside the Gaussian/categorical mocks. The corrected safety file passes 18 assertions. Installed-layout verification runs in a separate scratch test directory, preserving the original full-check archive.

## 2026-09-18T20:46Z — client inventory and generated transport documentation

Full client check: 25,476 passes, 45 skips, four inventory/retry-fixture failures; three check warning categories. Add the grid endpoint and Synopsis PREPARE to the shared AST-construction inventory (15 entries), and the already-audited grid endpoint to the explicit retry test. Targeted client audit passes 99 assertions. Regenerate only the two stale transport Rd files from their existing roxygen/function definitions. Two pre-existing warnings concern MI Unicode printing and duplicate ordinal documentation; a three-line semantics-preserving patch is prepared, awaiting the user because other-family edits were prohibited. No package version changes.

## 2026-09-18T20:50Z — installed namespace audits and transport fixture metadata

Four shared Synopsis test files passed under pkgload but falsely reported missing internals under installed checks because `vapply(exists, ...)` searched its calling environment. Explicitly inspect `asNamespace("dsVert")` without inheritance; this activates their existing tests rather than skipping them. The real-worker transport fixture also lacked the now-required signed projection metadata/public layout and a multiplication producer label; populate those fields consistently with its legacy full-vector fixture. No production validator changes. The two selected transport tests pass **1213 assertions**, including real workers, in `transport-check-corrected-targeted.log`.

## 2026-09-18T20:55Z — independent validation-cell concurrency

Sequential DSLite framing dominates elapsed time. Schedule at most three independent (family,epsilon) cells on the pod and both K3 family campaigns on the Mac; each subsequently runs its own smaller K5 gate. Stop only the old waiting shell coordinators and adopt their live R children (pod718153, Mac22057), preserving all active computation. New jobs use GOMAXPROCS=2, GOMEMLIMIT=2GiB, GOGC=25; adopted jobs retain their original settings. No arithmetic, ABI, privacy parameter, transport cap, signature, dataset or release key changes. Each completed cell requires the original hash checks and exact oracle/cold-lifecycle markers before the scheduler declares success.

## 2026-09-18T21:00Z — PSI contract fixtures and existing endpoint documentation

The full check exposed stale PSI fixture expectations against the existing v4 aligned-dataset binding and `privacy_unit_id` descriptor field. Assert the current frozen fields and the default privacy-unit value; no PSI production change. Regenerate the existing PSI descriptor Rd (Markdown enabled) and add internal documentation for six already-registered Gaussian Synopsis/formal publication endpoints that lacked aliases. These documentation additions do not alter endpoint registration or formal promotion state. Targeted PSI/remote-surface files pass 191 assertions.

## 2026-09-18T21:13Z — preserve legacy semantics; correct stale golden only after baseline proof

The legacy source-contract fixture expected `79b06f...104`; current code emits `cad513...acfd`. Independent source-tree runs of frozen step-1 snapshot **15e1de2** and pre-materialiser **89ee9be** both emit exactly the latter hash and fail the same old expectation. Update only the golden fixture, retaining all three baseline/current logs. This is not a release-key change. The optional typed-blob constant audit similarly requires an explicit namespace for `vapply(get, ...)`; its runtime code is byte-identical to step 1. Corrected local files pass 328 assertions.

Respect Addendum 2 by running full suites once, then only the failed scopes after fixture/documentation corrections. The corrected archive packaging checks explicitly use `R CMD check --no-manual --no-tests`; these results are not represented as another full test-suite pass. Server packaging: zero errors/warnings, one pre-existing NOTE (unchanged duplicate local normalize formals and optional formal typed-blob hooks). Client packaging: zero errors, two pre-existing warnings pending the user-approved patch. Go source/binaries remain unchanged from the full-suite snapshot.

## 2026-09-18T21:23Z — cold-process packaged-binary deployment repair

The first required-size binomial/epsilon1 API release completed and matched the oracle bit for bit. The subsequent cold lifecycle check failed because the validation checkout contained the new Linux binary but the preceding SHA256SUMS. Explicit-path live peers worked; the fresh process correctly rejected packaged discovery with `SHA-256 mismatch`. Copy the complete already-verified four-platform bundle and its manifest from the frozen check archive. All four checksums now pass. A new direct signed-profile admission check at n2000 passes in fresh callr processes for both families without a binary override (`cold-admission-corrected.log`). No validator, helper arithmetic or signing rule changed.

The first harness cleans private state on exit; therefore that extra release cannot supply a complete 20-instance evidence cell. Archive its successful API equality and cold failure, then restart only the binomial/epsilon1-to-epsilon8 lane with fresh signed releases (PID960689). The other two lanes continue. The earlier coordinator retains its first-lane failure; the complete evidence validator, not that historical marker, will decide final matrix completeness.

## 2026-09-18T21:38Z — resumed; measured Poisson startup recovery

Use a 4GiB Go heap target for new Mac topology workers after the exact public Poisson shape cold/hot probe demonstrated 64.64 s cold compilation within the existing 120-second readiness window. Preserve the failed 2GiB run and adopt existing binomial work unchanged. Add a Poisson-only recovery mode to the topology coordinator; no source contract, circuit, worker timeout, privacy or transport cap is changed.

## 2026-09-18T21:56Z — bounded relay diagnostic, no protocol change

The synthetic n32/p10/grid8 binomial API diagnostic passes integer DP-oracle equality (572.189 s under concurrent Mac load). Function-stack samples place much of sampled exchange CPU in regex/base64 string handling; a one-second native sample also includes IPC and parsing. These observations do not isolate enough of total elapsed time to justify changing shared authenticated transport or caps. Retain current production code and active campaigns. The initial Rprof report includes repeated append headers as a pseudo-frame; its timings are diagnostic only, not a promotion benchmark. The reproduction script now strips subsequent headers before summarizing. No payloads or protected values are sampled.

## 2026-09-18T22:25Z — concurrent cold compilation reproduces startup overrun

The second Poisson K3 attempt again failed closed before readiness. Two
concurrent independent public-shape compiles with GOMAXPROCS=2,
GOMEMLIMIT=4GiB and GOGC=25 take **209.266947 / 210.008394 s**, versus
64.641451 s for the earlier single compile. Both exceed the unchanged
120-second readiness window; their public circuit bytes still match their
own authenticated cache reload. Evidence: `cold-poisson-k3-pair-{1,2}.log`;
reproduce by compiling `cold_shape_probe_test.go.txt` as a temporary Go test
and launching two instances of that test binary concurrently with those
settings. The diagnostic's readiness assertion correctly fails.

Use the existing harness's synchronous DSI aggregate-job implementation for
the Poisson topology retry, so each authority finishes startup before the
other starts. `validate_dslite_sync.R` changes only the test connector's
advertised aggregate capability; every call still passes through DSI and the
strict DSLite allowlist. Capability/dispatch regression passes in
`synchronous-connector-targeted.log`. No production R/Go source, arithmetic,
privacy parameter, signed capacity, frame cap or readiness/runtime lease is
changed. The original frozen harness and package hashes remain checked;
the additional wrapper has its own before/after hash check.

Poisson-only retry: `sh inst/cross-grid-v2/run_topology_validation_parallel_mac.sh
--restart-poisson-sync`, native session95496. The failed 4GiB attempt is
retained as `topology-poisson-k3-before-sync-start.log`. Binomial K3 and all
three pod lanes continue unchanged. Required completed real releases remain
3/12. Actual success of the synchronous full-size retry remains pending.

## 2026-09-18T22:53Z — preserve unrelated formal-family implementations

The full Go result is recorded as not green, not converted to a pass by changing unrelated family tests. Four formal GLM failures were already recorded in step 1; Cox schema failures reproduce on the step-1 pod source and its eleven-command CLI inventory is unchanged. Keep these baseline failures explicit in CHECKS_V2 while completing the new grid validation. Per-cell selection statistics may be reported after complete 20-key/two-real-release/cold-lifecycle/hash checks; the six-cell matrix validator remains the final aggregate gate.

## 2026-09-18T23:06Z — keep execution reports outside the installed package

Add CHECKS_V2 to the existing .Rbuildignore development-report pattern. Refresh only the server packaging check and input manifest; full test suites are not repeated for this packaging-only change. No package version or NEWS change is required.

## 2026-09-18T23:16Z — topology scope remains unchanged pending reviewer decision

Observed full-grid K3 DSLite throughput projects to tens of hours. Asked whether clause 7 permits the wiring gate at n10000/p10/grid2 alongside the completed full-envelope secure benchmarks. Keep grid50 running unless the reviewer explicitly authorizes a narrower validation grid. No production ABI, admission limit, privacy cap or route change is proposed.
