# Step 2 status — kernel and release

## 2026-09-18T12:45Z — resumed

Read STATUS_V1, DECISIONS_V1, NUMERIC_CERTIFICATE_V1, the cross-owner design,
and the binding arithmetic and validation-layer addenda. Both repositories
are clean on `feature/cross-owner-grids`. Server HEAD is `15e1de2`; client
HEAD is `cb26ecd`. No V2 milestones or interrupted edits exist in these
worktrees. V1 full-suite totals remain pending; they are not counted as passes.

`./pod4 'tail -5 /workspace/logs/install_r.log; ls /workspace/dsvert'`
confirmed `R_STACK_DONE`. New work uses `/workspace/dsvert/crossowner-v2`
without modifying the other lanes present on the pod.

Current milestone: certify and cost the replacement piecewise polynomial.
No production release route has been enabled. Full suites will run only after
implementation is frozen; development uses targeted checks.

## 2026-09-18T13:05Z — numerical component and protocol probe

Completed a test-only arithmetic/cost experiment, not the fused producer.
The reproducible interval generator emits 30 candidate quadratic profiles,
shared integer fixtures, log-factorial tables and proposed envelope caps.
The original q64 profile, signed contract, source ABI and both release
allowlists remain unchanged. New candidates are explicitly rejected by V1.

Verification commands, from the package root unless stated otherwise:

```
python3 inst/cross-grid-v2/generate_profile.py --check
Rscript inst/cross-grid-v2/validate_profile.R
(cd inst/dsvert-mpc && go test -run '^TestCrossGrid(V1|PWV2)' -count=1 -json)
# From the workspace, for each package name:
PROCESSX_NOTIFY_OLD_SIGCHLD=true Rscript -e 'r <- testthat::test_local("dsVert", filter="dp-glm-grid-cross", reporter="silent", stop_on_failure=FALSE, stop_on_warning=FALSE); d <- as.data.frame(r); print(colSums(d[,c("nb","failed","skipped","error","warning","passed")]))'
Rscript inst/cross-grid-v2/benchmark_profile.R .
```

| Targeted gate | Before (V1 focused record) | After Mac | Fail/error/skip |
|---|---:|---:|---:|
| Go top-level tests | 8 | 14 | 0 |
| Go tests including subtests | 13 | 65 | 0 |
| Server R cross contract + integer assertions | 353 | 353 | 0 |
| Client R cross contract + integer + sensitivity assertions | 522 | 522 | 0 |

New arithmetic checks additionally cover 4290 shared integer vectors, 491550
dense points in each of R and Go, 990 independent high-precision comparisons,
1200 synthetic vector-adjacency checks, all 65536 uint8 optimizer input pairs,
and 16 real two-authority nonlinear evaluations. These are not DP releases.
Raw evidence is in `inst/cross-grid-v2/`; the three layer reports enumerate
exactly what has and has not been checked.

The K=64 component benchmark reports 2773–4019 AND gates/evaluation,
144–198 KB total protocol bytes/evaluation, 29–31 ms/evaluation on the Mac
and 268–398 ms/evaluation across the recorded pod runs. See BENCH_V2 for the
full per-family/domain table, public-size projections and timing limitations.
The cost gate FAILS. Full-domain Poisson's large certified interpolation error
also prevents claiming the required production utility gate.

The first pod archive extraction printed ownership/xattr warnings. Contents
were written successfully; matching SHA256 manifests subsequently verified
all three new Go sources and the profile fixture before accepting pod evidence.
Other pod lanes were not modified. No layout/tooling decision required user
input.

The initial expanded pod targeted run omitted `inst/cross-grid-v1` from the
probe export: all six new tests passed, while seven V1 tests failed on missing
fixture files. That log is preserved as `go-pod-missing-fixtures.jsonl`.
Copied the unchanged V1 fixture directory and reran the same targeted command;
this is an export-layout correction, not a code or expectation change.

## 2026-09-18T13:08Z — final checkpoint: NOT DONE

The corrected pod export passes 14 Go top-level tests / 65 including subtests,
zero failures or skips. The pod also reproduces the interval certificate and
passes the pure-R fixture, dense and sensitivity checks. Evidence:
`go-pod-targeted.jsonl` and `r-pod-profile.log`. Pod runs used Go 1.25.7 and
R 4.6.1; Mac runs used Go 1.25.7 and R 4.5.2.

| Requested deliverable | Completion at this checkpoint |
|---|---|
| 1. Fused typed Go kernel + joint noise/release | NOT DONE. Certified test-only nonlinear candidates and real Yao/KOS component comparisons exist; measured candidate fails cost gate. |
| 2. Full Mac/pod n,p,grid benchmark matrix | NOT DONE. Component probes, actual gates/bytes and explicitly labelled projections recorded in BENCH_V2. |
| 3. Server materializer/release lifecycle | NOT DONE. No production route or state was changed. |
| 4. Client cross-owner routes/DP selection | NOT DONE. Client remains at `cb26ecd`, clean. |
| 5. Layered E2E/selection/check campaign | NOT DONE. Component evidence only; 120 oracle DP selections, 12 DSLite releases, direct callr lifecycle, full suites and R CMD check remain unrun. |
| 6. Production API documentation | NOT DONE. Development/evidence docs supplied; no API changes to document or version bump to make. |

Commits on server `feature/cross-owner-grids`:

- `50948c4`: resumed scope and arithmetic-gate decisions.
- `2ba2eba`: interval profiles, independent references, component circuit and
  real-protocol tests, layer-specific evidence and explicit admission exclusion.
- `c10bc0d`: Mac/pod benchmark driver, raw logs, matching source hashes, failed
  cost gate and corrected pod targeted-suite evidence.
- This final STATUS-only checkpoint is identified by `git log -1 -- STATUS_V2.md`.

Reproduction is in BENCH_V2 and `inst/cross-grid-v2/README.md`. The pod export is
`/workspace/dsvert/crossowner-v2/dsVert`; logs are in its sibling `logs/` directory.
No full-suite pass, pre-existing NOTE classification, exact grid release,
selection agreement, 30-minute workload result or promotion is claimed.

Remaining first step: obtain an arithmetic design satisfying BOTH the cost and
production utility gates, with a new certificate, before binding the new profile
into the frozen source/release lifecycle. This is unfinished implementation,
not a missing user decision or unavailable tool; no BLOCKED_V2 file is created.
No tags, remotes, existing production code or client files were modified.

## 2026-09-18T13:12Z — resumed under reviewer Addendum 3

Both repositories are clean on feature/cross-owner-grids; server HEAD 296e242,
client HEAD cb26ecd. Read the checkpoint, benchmark, V1 contracts/certificate,
design and decisions before editing. Pod again confirms R_STACK_DONE.
The reviewer now accepts <=5000 AND/evaluation and <=60 GB measured aggregate
traffic at full size. Earlier cost-failure conclusions are historical and
superseded, not new blockers. Whole-release traffic/time remains unmeasured.
First work: range-reduced Poisson certificate and exact integer/circuit tests.
No completed milestone is being rerun.

## 2026-09-18T13:25Z — range-reduced arithmetic passes

Added the new Poisson candidate certificate, independent R/Go integer oracles,
shared fixtures and bit-exact circuit tests. Generator --check passes; pure R
passes 1611 fixtures, 983055 dense points and 6000 adjacency checks. Targeted
Go arithmetic adds 2 top-level / 8 including-subtest passes (no failures),
983055 dense points and 975 independent high-precision comparisons.
Commands and proof are in `inst/cross-grid-v2/EXP_REDUCED_CERTIFICATE.md`.
K64 measures 3540 AND/evaluation, with error 3.17234243e-5 at A4 and 1.43799821
at A16. It is not admitted and does not constitute the fused producer.

## 2026-09-18T13:34Z — batched two-authority components and compact framing

Mac targeted tests pass 14 top-level / 32 including-subtest tests, zero failures
or skips. Eight top-level tests are existing protocol/encrypted-record checks;
six are new range-reduced/binomial component and admission-exclusion tests.
The corresponding pre-edit run of this exact combined selection does not exist;
no before-count is inferred from the different historical 14/65 selection.

The new opt-in framing commits the circuit topology before OT and eliminates
redundant gate-row lengths. Existing callers continue using the old framing.
32-evaluation encrypted net.Pipe measurements: binomial A4 2805.969 AND and
~94036 B/evaluation, binomial A16 3077.969 AND and ~102747 B/evaluation;
Poisson 3540.969 AND and ~117570 B/evaluation. Whole-release gates remain open.
The pure-R pooled objective comparison also passes both families; see Layer 1.

The first pod arithmetic/transport selection passed, then the local probe was
extended with the binomial batch and explicit V1 exclusion tests. A final pod
rerun of that changed selection plus both-family component benchmarks is running
under nohup with GOMAXPROCS=8. No full suite or R CMD check has been run in V2.

## 2026-09-18T13:39Z — final component evidence on Mac and pod

The final nohup pod run prints EXP_REDUCED_POD_DONE and reproduces 14 Go
top-level / 32 including-subtest passes, zero failures/skips; R arithmetic,
certificate reproduction and pooled glm checks pass. Verified all 464 source,
module and fixture hashes against the Mac export. Focused commands are recorded
in SECURE_INTEGER_V2 and the checked-in pod runner; raw logs are under
`inst/cross-grid-v2/pod-exp-reduced/`. An initial tar attempt emitted ownership
warnings; re-export with --no-xattrs / --no-same-owner and the full hash check
resolved that layout issue before accepting evidence.

Compact batch32 component measurements (Mac / pod):

| Family/domain | AND/eval | wire B/eval | ms/eval Mac / pod |
|---|---:|---:|---:|
| Binomial A4 | 2805.969 | ~94036 | 3.085 / 20.854 |
| Binomial A16 | 3077.969 | ~102747 | 3.087 / 33.419 |
| Poisson A<=16 | 3540.969 | ~117570 | 4.647 / 28.204 |

The nonlinear AND gate passes the revised threshold. The measured whole-release
60-GB and pod elapsed-time gates remain NOT RUN. BENCH_V2 explicitly separates
measurements from projections, including the small remaining Poisson byte budget.
No production dispatch, server/client route, same-owner R path, tag or remote
was changed. The shared Go protocol core changed only through opt-in framing;
its legacy entry points and targeted tests retain prior behavior.

## 2026-09-18T13:39Z — final checkpoint: NOT DONE

This resume completes a certified range-reduced Poisson candidate, exact
arithmetic/component tests, synthetic pooled objective comparisons and measured
Mac/pod compact-transport probes. It does **not** complete Task V1 / Step 2.
There is no external blocker or unanswered question; remaining work is unfinished
engineering. No BLOCKED_V2.md is created and no promotion is requested.

| Deliverable | Done / not done |
|---|---|
| 1. Fused typed kernel + joint DP release | **NOT DONE.** Nonlinear candidates, Go/R oracles and real two-authority component tests pass. Complete f100 source/predictor, private alignment/validity, bounded outcomes/log-factorial, clamped candidate sums, signed new-profile admission and joint noise/release are absent. |
| 2. Full n,p,grid Mac/pod benchmark matrix | **NOT DONE.** Scalar/batch32 component measurements and source hashes are recorded. No full-size release, measured 60-GB gate or measured 30-minute workload result. |
| 3. Server materializer and release lifecycle | **NOT DONE.** No server R dispatch/state change; direct callr admission/sticky/exactly-once/crash tests remain unrun. |
| 4. Client routes and DP-best selection | **NOT DONE.** dsVertClient remains clean at cb26ecd; cross-owner release is not enabled. |
| 5. Layered validation and package checks | **NOT DONE.** Layer-1 candidate arithmetic/pooled glm and Layer-2 component tests pass. Production-bound mathematics, full secure integer/lifecycle, 120 oracle DP selections, 12 real DSLite releases, full suites and R CMD check remain unrun. |
| 6. Production API documentation | **NOT DONE.** Candidate proof and evidence docs updated only. No production R functions changed, no roxygen/API-state claim and no NEWS/DESCRIPTION version bump. |

Exact implementation/evidence commits on dsVert feature/cross-owner-grids:

- b270ebe — resume and revised cost gate.
- 2751630 — certified range-reduced Poisson and exact R/Go/circuit arithmetic.
- 0006f1a — opt-in topology-bound framing, both batched components and pooled R objective tests.
- 699636e — final matching Mac/pod evidence and measured component benchmark report.
- This STATUS-only checkpoint is identified by `git log -1 -- STATUS_V2.md`.

Reproduction, from dsVert:

```
python3 inst/cross-grid-v2/generate_exp_reduced.py --check
Rscript inst/cross-grid-v2/validate_pooled_objective.R
(cd inst/dsvert-mpc && go test -run '^(TestCrossGridExpReducedV2|TestCrossGridBinomialV2BatchProtocol$|TestExactGCProtocolEndToEnd$|TestExactGCProtocolFreshArithmeticShares$|TestExactGCSecureRecords)' -json -count=1)
Rscript inst/cross-grid-v2/benchmark_exp_reduced.R .
```

The pooled driver also checks both profile arithmetic oracles. Pod reproduction
uses the nohup command in BENCH_V2 and the matching-source export at
`/workspace/dsvert/crossowner-v2/dsVert`. Final raw pod logs are committed in
`inst/cross-grid-v2/pod-exp-reduced/`; all selected tests pass 14 top-level /
32 including subtests on both machines. Historical V1 full-suite uncertainties
have not been relabelled as passes or pre-existing R CMD check NOTEs.

Resume with the full fused source/loss kernel and explicit signed admission for
the new certified profile identities, retaining the old V1 contracts unchanged.
Then measure the full release's traffic/time, integrate the authenticated server
and client lifecycle, and execute the outstanding layer-2/layer-3/DSLite gates.
The nonlinear design no longer needs another wide-domain Poisson interpolation
experiment; the full release budget still requires measurement. No tags or
remote branches were modified; nothing was pushed.

## 2026-09-18T13:43Z — resumed under Addendum 4

Both worktrees are clean on feature/cross-owner-grids. The accepted component
checkpoint is retained. R_STACK_DONE is confirmed on the pod. Implement the
fused source/loss producer next, then the measured release and lifecycle gates.
No full-suite rerun is started during development.

## 2026-09-18T14:17Z — fused integer kernel and real joint-noise composition

Implemented an internal bounded typed producer for both families, exact local
f100 share predictors, private source/complete-case/alignment validation,
certified profile evaluation, bounded outcome/log-factorial, ties-even/clamped
candidate sums and encrypted two-authority masked outputs. The ordinary exact
compiler rejects this specialized operation. R admission is not enabled.

Mac targeted selection passes 17 top-level tests / 35 including subtests, zero
failures/skips (final log: inst/cross-grid-v2/fused-targeted-mac.jsonl). The
matching before-selection was not run; historical counts are not substituted.
R passes 288 independent full f100-to-loss fixtures; Go/circuit comparisons
cover those fixtures plus 80 randomized/malformed instances. Both families
pass real encrypted net.Pipe kernel-to-joint-vector-Laplace equality against
the seeded noise oracle at epsilon=4, delta=2^-100. These are not authorized
releases, not DSLite, and not the required 12 wiring releases.

The first pod export omitted the unchanged R limb helper. Added it to the
export and hash manifest and reran; no assertion or expectation was changed.
A prior pod export retained the renamed test-only optimizer, causing duplicate
definitions; removed only that obsolete file in this task's dedicated lane.
No other pod lane was changed. Final certified-cap benchmark is running under
nohup; earlier stress-cap measurements are explicitly exploratory.

Reproduction/proof boundaries are in inst/cross-grid-v2/FUSED_KERNEL_V2.md.
Full workloads, signed admission/lifecycle, client, statistical/wiring gates
and full package checks remain open. No protected values entered any log.

## 2026-09-18T14:42Z — final resource-gate finding: BLOCKED / NOT DONE

The final Mac and pod focused runs pass **18 top-level Go tests / 36 including
subtests**, zero failures/skips. The preceding focused checkpoint was 17/35;
adding the endpoint/slack regression gives the 18/36 count. Signed half-tie and
adjacent-point checks and deliberate small-cap saturation also pass. These are
focused development counts, not frozen-baseline or full-suite counts. The
independent R driver passes 288 full-dot fixtures on both machines. Both
reproducible Python artifacts pass --check with mpmath 1.3.0. All **468** final
source/module/fixture/driver hashes match the pod export. Raw final logs:
`inst/cross-grid-v2/fused-targeted-{mac,pod}.jsonl`, `fused-r-{mac,pod}.log`,
and `fused-source-check-pod.log`.

Go is 1.25.7 on both hosts; R is 4.5.2 on Mac and 4.6.1 on the pod. The Mac
certificate interpreter is /opt/homebrew/opt/python@3.11/bin/python3.11. An
alternate python3 selected in a package working directory lacked mpmath;
selected the existing 3.11 interpreter and reproduced both files successfully.
No tooling choice is left unresolved.

Certified-cap, distinct-candidate, 32-row / p10 / 8-candidate measurements:

| Family | AND/batch | Aggregate wire bytes/batch | Wall seconds Mac / pod |
|---|---:|---:|---:|
| Binomial | 1076415 | 42404496 | 1.478935959 / 7.319170999 |
| Poisson | 1399391 | 52745381 | 2.308600250 / 7.605694722 |

The pod nohup benchmark finished with FUSED_POD_DONE. Compilation is excluded
from those times. These are source/loss batches, not authenticated DP releases.
At n10000/grid50, 1872 complete batches alone require **64.481564160 GB** and
**83.829118464 GB** of garbled tables respectively. Those exact lower bounds
already exceed the binding 60-GB gate before tail batches, OT, source/input
transport, joint noise or release authentication. Poisson's full-kernel AND
count is also 5466.371/evaluation. **The full-size gate FAILS.** BENCH_V2 records
measured batch traffic separately from full-size lower bounds and projections.

No n2000 or n10000 whole release was run; no measured >30-minute or <=30-minute
whole-release result is claimed. No approved cheaper complete route is claimed.
The current all-Boolean implementation cannot satisfy the frozen cost contract;
BLOCKED_V2 records the precise reviewer question, evidence and limitations.
This is not a claim that every alternative MPC architecture is impossible.
Production admission remains closed, pending a resource-compliant design or an
explicitly revised acceptance contract.

### Done / not done

| Requested deliverable | Final status |
|---|---|
| 1. Fused Go producer + joint release route | **PARTIAL / NOT DONE.** Internal typed source/loss kernel, private masks, Go/R equality, endpoint/slack/saturation and real kernel-to-joint-noise tests pass. Signed producer admission, durable binding/evidence and the production exact_gc_to_joint_dp_vector_v1 route are absent. |
| 2. Full benchmark matrix, n2000/n10000 release measurements | **NOT DONE; RESOURCE GATE FAILS.** Certified-cap fused batch measured on both hosts, Go benchmark and small R driver supplied. Full release traffic/time and the requested n,p,grid matrix are not measured. |
| 3. Server materializer and authenticated lifecycle | **NOT DONE.** No R dispatch, source adapter, sticky/exactly-once injection, crash/resume or direct callr lifecycle integration. |
| 4. Client cross-owner acceptance and DP-best docs | **NOT DONE.** Client remains clean at cb26ecd; no new route is enabled. |
| 5. Layered validation / full checks | **NOT DONE.** Component/full-integer mathematics and Go net.Pipe composition pass. 120 oracle selections, 12 actual DSLite API releases, lifecycle tests, full suites and R CMD check remain unrun. No pre-existing NOTE classification is asserted. |
| 6. Production API docs | **NOT DONE.** Internal proof, benchmark and layer reports are updated; production roxygen/package route docs await an implemented route. No NEWS/DESCRIPTION version bump. |

### Exact commits and reproduction

New server commits on feature/cross-owner-grids:

- `8b6c7bf` — resumed state and exact f100 share-predictor decision.
- `2771a99` — internal fused producer, private protocol, integer oracles and
  real joint-noise composition; no public admission.
- `2f36f79` — certified-cap Mac/pod benchmarks, endpoint/slack tests, failed
  resource-gate report and evidence.
- The final reporting/R-driver/saturation-evidence commit is identified by
  `git log -1 -- STATUS_V2.md` (this file cannot include its own commit hash).

Client remains `cb26ecd`. No tags, remote branches or existing production R
routes were modified; nothing was pushed.

From dsVert, with a Python interpreter containing mpmath 1.3.0:

```
python3 inst/cross-grid-v2/generate_kernel_profiles.py --check
python3 inst/cross-grid-v2/generate_fused_vectors.py --check
Rscript inst/cross-grid-v2/validate_fused_vectors.R
Rscript inst/cross-grid-v2/benchmark_fused_batch.R .
```

The small R benchmark driver is syntax-checked and invokes the exact Go command
used for the measured runs. The focused Go command, widths and admission limits
are in inst/cross-grid-v2/FUSED_KERNEL_V2.md. The pod runner and hash manifests
are in that directory; the working export remains
`/workspace/dsvert/crossowner-v2/dsVert`, with logs in its sibling logs directory.
The timed pod snapshot preceded only the generic-compiler rejection guard and
later test additions; the numerical/compiler-profile/specialized-runner code is
unchanged. The final focused run verifies the final source snapshot separately.

All created numerical inputs are public synthetic fixtures. There are no
protected values in the evidence. No promotion or end-to-end completion is
claimed. The next necessary work is resolving the failed resource design before
authorized server/client release integration can meet the requested gate.

## 2026-09-18T14:46:35+00:00 — resumed under Addendum 5

Both worktrees are clean on feature/cross-owner-grids. R_STACK_DONE is
confirmed. The prior resource blocker is resolved by the reviewer: retain
the full envelope and fused design; measure <=110 GB and <=4 h on the pod.
First measure all row/candidate batches and joint noise at n2000/n10000,
then complete signed admission, lifecycle, client and layered validation.
Historical NOT DONE entries remain accurate until superseded by evidence.

## 2026-09-18T14:58Z — signed profile admission tests

Added explicit piecewise-profile contract construction/admission on server and
client, with a new hash-pinned interval cap table for all M=1..1024. Both sides
reconstruct caps, numeric metadata and signatures; legacy contracts retain V1.
Targeted contract tests: server 175 before / 197 after; client 260 before /
282 after, zero failures/errors. Commands: testthat::test_local(package,
filter="dp-glm-grid-cross-contract"). Raw logs are profile-admission-{server,client}.log.
The Python generator reproduces admission_certificate.json; the worker and
production release path remain under development. No R route is enabled yet.

The full-workload benchmark smoke test passes both families (3 rows, p5,
9 candidates including a tail); all integer and joint-noise outputs match.
The pod n2000 then n10000 campaign is running under nohup from
run_full_measurement_pod.sh with 48 peer pairs. Its source snapshot is b88f986,
verified by full-measurement-source.sha256. These computations exclude the
unfinished R lifecycle and will not be labelled authenticated releases.

## 2026-09-18T15:00Z — durable Go worker integration

Both-family encrypted durable-spool workers now match the integer oracle,
remove source-bearing configs and reject terminal spool reuse. Targeted run:
5 top-level / 11 including-subtest passes, zero failures/skips. It includes the
existing config unlink test and the two-authority/joint-noise regressions.
Command: go test -run '^(TestCrossGridDurableWorkers|TestExactGCWorkerConfigIsOneLinkAndRemovedBeforeUse|TestCrossGridKernelPurposeAndAdmissionGate|TestCrossGridKernelTwoAuthority|TestCrossGridKernelJointNoise)$' -count=1 -v.
Evidence: worker-targeted-mac.log. The initial durable test stalled because the
fused runner omitted exactGCFinishConn; the corrected run completes in 3.291s.
This verifies worker persistence, not the pending R signed lifecycle.

## 2026-09-18T15:03Z — pod scheduling correction

The visible 96-vCPU count overstates this container's quota (7.65 CPU cores).
Stopped the n2000 compile-only attempt and retained its interrupted log.
No n10000 attempt had begun. Runner now uses four peer pairs/GOMAXPROCS=8
and source-identical circuit reuse. Both-family n3/p5/grid17 smoke test passes
including joint-noise equality and candidate tails. The matching-source pod
campaign is restarted with the acknowledgement-drain fix included.

## 2026-09-18T15:20Z — retry-safe worker masks and noise chunking

Focused Go checks pass 4 top-level / 6 including-subtest tests, zero failures.
The seeded mask regression preserves output shares across fresh sessions and
fresh source sharing. Public worker planning also checks source/type limits.
The 50-candidate smoke passes all candidate batches and admitted joint-noise
chunks for both families (binomial 171.37s; Poisson 189.61s on Mac). Noise alone
adds about 0.98 GB for binomial in this test; the full gate must include it.

The previous n2000 binomial kernel completed; the harness then rejected its
oversized unchunked noise call. Its log is retained on pod as
full-n2000-noise-shape-failure.log; this is not a completed release. Corrected
campaign now runs n10000 before n2000. No successful full-size run is repeated.

## 2026-09-18T15:44Z — materialiser/lifecycle implementation, targeted gates

- Server targeted command: `Rscript -e 'r <- testthat::test_local(".", filter="dp-glm-grid-cross-contract|dp-gaussian-cross$", reporter="summary", stop_on_failure=FALSE); d <- as.data.frame(r); print(colSums(d[,c("nb","failed","error","passed")]))'` — **285 assertions, 0 failures/errors** (`inst/cross-grid-v2/lifecycle-targeted.log`). Includes actual separate `callr` processes writing/reopening the MAC-authenticated result store, replay equality, record-change rejection, tamper rejection, missing-result rejection, and snapshot normalization. This is not yet the full authenticated remote crash/resume gate.
- Client targeted contract/selection command, filter `dp-glm-grid-cross-contract|dp-glm-grid$`: **318 assertions, 0 failures/errors**. Earlier complete grid filter: 578 assertions green. New cases check signatures, caps/profile/wrapper tampering, signed candidate selection and qualified formula syntax.
- Full-size pod benchmark continues (4 concurrent pairs under measured 7.65-core effective quota). No completed full-size family result yet at this milestone.
- Real DSLite validation harness added using the package's existing isolated two-peer scaffold. Initial setup exposed the existing prohibition on noise-root storage beneath the server package tree; state moved into ignored client build directory. PSI minimum capacity is retained at 64. **No DSLite grid release is claimed yet.** Full authenticated lifecycle/wiring, oracle selection campaign and final checks remain NOT DONE.

## 2026-09-18T15:58Z — layer-1 candidate objective gate

- `go test -c -o ../cross-grid-v2/build/cross-grid-oracle.test` builds a test-only adapter, with no installed plaintext/noise command.
- `Rscript inst/cross-grid-v2/validate_layered_math.R ..` — **40 n=2000/p=6 instances, 80 candidate objectives PASS** against independent R family deviance/saturated-constant evaluation, within certified profile + lattice error. `LAYER1_V2.md` links per-instance evidence.
- Additional cross-package admission sanity: a client-generated/signed V2 contract is accepted by the server validator (`cross-package-profile.log`). The remaining DSLite failure is specifically the actual catalog's derived alignment-contract hash; debugging is confined to public schema/contract metadata. No secure grid/DP release success is claimed yet.

## 2026-09-18T16:13Z — first measured full-size pod gate PASS

- **Binomial n=10000/p=10/grid=50:** 86,515,842,839 bytes; 2,795.701 s (46m 36s), 2,191 batches, integer + joint-DP oracle equality. Revised <=110 GB / <=4 h gate PASS. Original 30-minute target exceeded and prominently recorded in BENCH_V2. This is the synthetic Go kernel+noise path, not a DataSHIELD framing measurement.
- Poisson full-size run has started; both n=2000 runs follow in the same nohup campaign. Raw pod evidence copied to `inst/cross-grid-v2/pod-full-n10000.log`.
- New client source geometry, authorized source-computation session, and explicit JSON framing are exercised by DSLite. The next required integration step is a server-minted typed start (added to the same authenticated lifecycle); no generic start route is exposed.
- Paired-namespace targeted client tests: **710 assertions, 0 failures/errors**, filter `^dsi-text-frame$|dp-glm-grid-cross-contract|dp-glm-grid$`, including the exact newly expanded remote method/formal inventory.
- Layer 1 now also compares all 80 n=2000 candidate losses with an independent 80-digit mpmath reference; all PASS.
- Gate revision file now also contains clause 7 (K=3 and K=5 owner-topology releases). Kernel ABI already supports 2..64 owners; topology validation remains outstanding in addition to the original 12 two-peer releases. No topology evidence is claimed yet.

## 2026-09-18T16:26Z — typed worker wiring

Authenticated start uses server-minted typed state keys. A source/base64 mismatch found by the real DSLite harness is corrected at staging (including the private output mask seed); final stored shares use the same strict worker encoding. Targeted server contract file: **252 assertions, 0 failures/errors** (`staging-targeted.log`). Real DSLite completion remains pending. Packaged Go binaries rebuilt with the repository Makefile for all four supported platforms.

## 2026-09-18T16:43Z — scoped one-draw sampler correction

- The n=4 DSLite grid computation and DP publication completed, but the independent oracle gate rejected it: the legacy policy used convolution and the catalog added numeric moments. This is explicitly **not** a qualifying wiring release.
- Corrected both new-family-only paths: count-plus-grid catalog and explicit <=51-coordinate joint exact-GC policy, using globally calibrated noise chunks. Existing sampler default remains dimension 1.
- Targeted server contract + exact-noise adapter: **337 assertions, 0 failures/errors**. Client exact-noise + Synopsis adapter: **98 assertions, 0 failures/errors**, including legacy geometry and partial noise chunks. Fresh real/oracle smoke runs are in progress.
- Remaining pod matrix queued under nohup PID 366920 after `FULL_MEASUREMENT_POD_DONE`; it excludes the already measured n10000/p10/grid50 configuration. No benchmark source is overwritten.

## 2026-09-18T16:53Z — first actual one-draw DSLite equality (small smoke)

Binomial n=4/p=6/grid=2, epsilon=4: **real two-authority joint exact-GC DP vector bit-for-bit equal to the oracle**, selected candidate also equal; client elapsed 342.114 s under concurrent Mac matrix load. Evidence: `dslite-binomial-n4-first-bitwise.log`. The computation/certificate assertion completed, then Rscript reported a trailing parse error because its source file had been edited while R was incrementally reading it. This is not a clean script exit or one of the required n2000 releases. Subsequent invocations use `Rscript -e 'source("inst/cross-grid-v2/validate_dslite.R")' ..` to parse the complete source before execution.

Client source-owner Claim coverage is now independent of public moment blocks; targeted contract/grid tests **320 assertions green**, including K=3 source coverage. The 20-instance n2000 oracle pilot is running. Final campaigns will plan production seeds/contracts for every instance and additionally run the first two through the real client, so the 12 real releases are a subset of the 120 reported selections.

## 2026-09-18T17:00Z — both full-size pod arithmetic/traffic gates PASS

Poisson n10000/p10/grid50 completes at **106,763,755,314 bytes / 2695.032 s**, with integer and joint-noise oracle equality. Binomial remains **86,515,842,839 bytes / 2795.701 s**. Both below the revised 110 GB / 4 h ceiling; both above the original 30-minute target. `BENCH_V2.md` reports phase costs, fused AND counts, CPU quota and the exact measurement scope. The nohup runner continues to both n2000 cases.

Mac RAM is 16 GiB and concurrent validation caused memory pressure. The unnecessary extra oracle-only n2000 pilot was stopped during PSI (no selection outputs); final mixed campaigns share one PSI alignment with their two real releases. This does not count toward the required 120 selections.

## 2026-09-18T17:12Z — planned-vs-production equality and queued full validation

- A second n4 binomial real release matches a **separately prepared production sticky-seed/worker contract**, then matches the complete authenticated oracle DP vector. Cold-process record checks passed admission, persisted-share replay, original-aggregate injection and changed-key rejection; the tamper assertion expected a public-boundary error class from an internal function. The helper now applies the actual public transcript boundary before asserting that class/message. That prior harness exit is retained as `dslite-binomial-n4-planned-bitwise.log`, not counted as a clean full validation.
- Poisson n4 interruption/retry + cold-record smoke is running.
- Pod validation has a separate checkout: `/workspace/dsvert/crossowner-v2/validation/` (server snapshot c734c10, client bc72306 plus the three source-tree validation helpers). No benchmark source is overwritten. Nohup campaign PID **415691** waits for full measurement completion, then runs two family lanes, each epsilon 1/4/8, n2000/p6/grid2, 20 signed grids, with the first two real releases checked against their independently prepared oracle policies/seeds and vectors. Helper file hashes are checked before/after each cell.
- Oracle row/candidate-tail regression: both families PASS (35 rows, 10 candidates, three owners), `oracle-chunks.log`.
