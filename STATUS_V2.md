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

## 2026-09-18T17:21Z — Poisson interrupted-release and fresh-process record gate PASS

`DSVERT_GRID_VALIDATION_FAMILY=poisson DSVERT_GRID_VALIDATION_COLD=1 DSVERT_GRID_VALIDATION_INTERRUPT=1 Rscript -e 'source("inst/cross-grid-v2/validate_dslite.R")' ..` exits cleanly. It deliberately interrupts after durable secure batches, retries the same signed grid in a new computation session, and proves equality of production/planned sticky seeds and the complete authenticated DP vector. Fresh R processes re-authenticate the signed contract and read snapshots of the actual pre-compaction private records: original-aggregate exactly-once injection, identical replay, changed-key rejection and transcript-safe MAC-tamper rejection all PASS for both authorities. These record snapshots test persistence without defeating the production post-publication compaction tombstones. n4/p6/grid2, epsilon4; successful retry client elapsed 201.144 s. This is additional lifecycle evidence, not one of the required n2000 releases.

Final targeted no-fallback guard tests: server **338 assertions green**; client **322 assertions green**. New grids reject non-Laplace catalogs rather than silently using an older non-MPC release. The required delta=2^-100 matrix is unchanged. Those three guarded R files were copied to the isolated pod validation checkout before campaign start.

## 2026-09-18T17:33Z — resumed; n2000 measurement complete

Both n2000/p10/grid50 pod measurements pass integer and joint-noise oracle equality: binomial **18,085,815,835 bytes / 630.821 s**; Poisson **22,172,826,365 bytes / 744.277 s**. Raw evidence: `inst/cross-grid-v2/pod-full-n2000.log`. Same explicitly unauthenticated Go measurement scope as the n10000 benchmark.

The first pod validation attempt failed closed before identity creation: the `/workspace` mount reports mode 0777 even after requesting 0700. Restarted the unchanged security checks with ephemeral custodian state under verified mode-0700 `/tmp/dsvert-crossowner-v2-state`; code and evidence remain in the dedicated workspace lane. Nohup campaign PID **447927**, same 120 oracle/12 real matrix, helper hashes checked per cell. No failed attempt is counted as a release. Remaining pod and Mac benchmark matrices continue.

## 2026-09-18T17:35Z — private state location corrected; topology campaign

The `/tmp` attempt also failed before release: production noise roots explicitly reject temporary trees. The final synthetic state parent is `/var/lib/dsvert-crossowner-v2-validation`, verified root-owned mode 0700. No permission/noise-root validation is bypassed. Matrix restart PID **450578**.

Additional clause-7 topology campaign uses the same hash-frozen harness and two compute/noise authorities: per family K3 at **n10000/p10/grid50**, and K5 at the explicitly smaller **n2000/p6/grid2**, epsilon4. Each release requires real multi-owner PSI, all signatures, full integer DP-vector oracle equality, DP selection equality and fresh-process record checks. Runner: `inst/cross-grid-v2/run_topology_validation_pod.sh`. These four releases are additional to, and not counted in, the 120/12 matrix.

## 2026-09-18T17:47Z — serialized pod validation after memory exhaustion

Concurrent large PSI setups reached the actual 50,000,000,000-byte cgroup memory ceiling (observed peak 50,000,023,552; fail counter 11). Binomial's R process segfaulted during polling; the other lanes failed closed during PSI transport. No alignment/release completed. A surviving worker held approximately 33 GB RSS, then exited before cleanup. Failure logs are retained on the pod in `logs/failed-concurrent-psi/`.

Restarted the matrix sequentially by family under `GOMEMLIMIT=6GiB`, `GOGC=25`, two Go scheduler threads per worker (PID **458353**). The topology runner (PID **458354**) waits for successful completion of that matrix and also runs families sequentially. These are runtime scheduling/GC controls only; no circuit, capacity, transcript, privacy or admission limit changes. The remaining raw benchmark matrix still runs with its previously frozen settings.

## 2026-09-18T17:54Z — benchmark recovery and full-check queue

The remaining matrix runner was no longer alive; its n1000/p5/grid50 binomial FULL_MEASUREMENT record is complete, while Poisson stopped during joint noise. No completed n10000/p10/grid50 measurement is repeated. `resume_matrix_pod.sh` (PID **466353**) skips completed family/configuration records and runs only missing ones with the unchanged frozen binary, adding GOMEMLIMIT=6GiB/GOGC=25. The evidence parser records interrupted logs and accepts only complete oracle-checked measurements; it separately enforces full-envelope resource gates.

Full checks are queued (PID **463014**) behind the remaining matrix to bound memory use. Frozen source archives: server **09b650b**, client **e4c55c0**, under `/var/lib/dsvert-crossowner-v2-checks` to retain real POSIX modes during packaging/tests. Code/evidence origins remain the dedicated workspace lane. R CMD check will run each package's full test suite; Go uses `go test ./... -count=1 -timeout=0`. Four missing optional R dependencies are being installed. No full-check pass is claimed yet.

## 2026-09-18T18:04Z — PSI capacity correction before validation retry

A second n2000 PSI attempt exhausted memory despite GC controls, before any release. Scalar comparison source now passes old-source bitwise equivalence (180 eight-coordinate masked vectors), existing big-int and net.Pipe protocol tests: 13 passing test/subtest results, 0 failures. `psi-scalar-targeted.log`. Pod n2048 compile: **52.009 s, 3,002,371 gates**. The n4096 probe correctly failed the existing 512 Ki-bit input cap; PSI chunk geometry is corrected to 2048 on both sides, with server/client schedule tests **6 / 19 assertions green**. Full checks had not started; their waiting runner was stopped to refresh the frozen archive after these required shared-infrastructure corrections.

## 2026-09-18T18:08Z — current gate table (supersedes historical checkpoint tables)

| Deliverable | Current evidence / remaining gate |
|---|---|
| Fused typed kernel and joint noise | Implemented; integer/R references, boundaries, real two-peer components and small real DSLite equality pass. |
| Benchmark matrix | Both full-size pod gates and both n2000 measurements pass. Mac 15/16 family/configuration records complete; final Poisson running. Remaining pod matrix resumed without repeating completed records. |
| Server release lifecycle | Materialisation, signatures, sticky binding and injection implemented; interrupted Poisson smoke and direct cold-process/tamper checks pass. Full n2000 wiring still pending after PSI corrections. |
| Client | Signed cross-owner acceptance, public preflight, transport and DP-best selection implemented and targeted tests pass. |
| Layered validation/checks | Layer 1 and component/cold-record Layer 2 pass. **NOT DONE:** 120 oracle selections, 12 n2000 real API matches, K3/K5 releases, full Go/R checks. |
| Documentation | Package docs and roxygen committed; final measured statistics and check results remain to be incorporated. Versions/NEWS unchanged. |

Worker/source transfer for server b542b84 and client ab56385 is in progress; binaries will be checksum-verified before restarting. No qualifying n2000 release is yet claimed.

## 2026-09-18T18:16Z — patched PSI worker reproducibly built on pod

Native pod `make linux` under Go 1.25.7 reproduces the packaged Linux SHA-256 exactly: `3817f526ca26f775def596defcaa17c5724969f4f7e56cac621ab5f5204105fe`. The slow multi-platform transfer to the validation checkout was stopped; only the Linux runtime is needed there. Full multi-platform source archive transfer continues separately for package checks. Server R and client R both use 2048-coordinate PSI chunks. The matrix is restarted from its first cell; no failed attempt is counted toward the required selections/releases.

## 2026-09-18T18:18Z — complete Mac benchmark matrix PASS

All **16 family/configuration measurements** for n1000/10000, p5/10, grid16/50 complete with integer and joint-DP oracle equality. `summarize_bench.py` verifies complete nonduplicate coverage and the full-envelope resource ceilings; table appended to BENCH_V2. Full-size Mac binomial **1017.426 s**, Poisson **1215.588 s** (see raw JSON for exact precision). Original runner and source snapshot retained; Mac has 16 GiB RAM and earlier cells overlap local validation, as already noted. No timing is presented as an isolated-machine benchmark.

Validation restart PID **496594** uses the checksum-matched native worker. Core dumps are now disabled in the validation/check runners and their owned running process trees after the earlier R segfault; no core file was found at the harness working-directory path.

## 2026-09-18T18:22Z — topology validation uses the now-idle Mac

Stopped the waiting pod topology runner before any new topology attempt. `run_topology_validation_mac.sh` now runs the four additional K3/K5 releases sequentially on the Mac (native exec session 36588): K3 n10000/p10/grid50 and K5 n2000/p6/grid2 for each family, epsilon4. The original 120/12 two-peer matrix remains on the pod. This overlaps independent work without adding large PSI jobs to the pod's 50 GB quota. Mac topology uses the rebuilt arm64 worker, GOMAXPROCS=2, GOMEMLIMIT=4GiB, GOGC=25 and the same hash-frozen synthetic harness. No statistical or public-capacity scope changed.

## 2026-09-18T18:30Z — large-envelope DSLite relay binding fixed

K3 initial reference-exchange failure is retained in `topology-binomial-k3-before-relay.log`. Minimal regression confirms public-UUID/private-storage-ID mismatch; **582 targeted relay/security assertions pass** after preserving both identities explicitly. `psi-relay-before.log` and `psi-relay-targeted.log` record before/after. K3 is restarted with all server/client R sources, inventories, native worker and harness helpers hashed before/after each topology release. Pod K2 has completed real n2000 PSI, signatures and public admission and is running the release. No qualifying DP-vector match has yet been recorded.

## 2026-09-18T18:34Z — bound large PSI membership sharing without raising caps

K3 passed the large-envelope relay after the UUID fix, then failed at private membership sharing: target matching passed the entire 16384-slot bucket to a Ring63 bit helper capped at 4096. The purpose-bound membership caller now shares fixed 2048-coordinate chunks and concatenates canonical Ring63 records. The existing bit-helper cap remains unchanged; small buckets produce exactly the same bytes under the same entropy. Full wire shape, encrypted-envelope context, signed capacity and membership semantics are unchanged.

Pure-R tests reconstruct all 16384 bits exactly, verify bounded entropy requests, reject wrong shapes/invalid bits, retain the old helper's oversized-vector rejection, and compare the small-bucket wire output with the original path. **89 assertions pass** across chunk/canonical Ring63 tests (`psi-membership-targeted.log`). This required shared PSI correction is recorded for other family lanes. The failed K3 attempt released no DP vector and remains `topology-binomial-k3-before-membership.log`.

## 2026-09-18T18:42Z — package-check inputs synchronized; integration still running

All **1376 runtime/test input hashes** match the pod check archive, including both packages and all four worker binaries (`final-check-inputs-preflight.log` on the pod). Server runtime/test sources correspond to **63d1c25**, client **ab56385**. Full suites have not started; the final check runner is prepared and will run after development integration settles. It verifies these inputs before and after testing.

Pod matrix PID 496594 has completed n2000 PSI alignment, custodial signatures and public admission and is executing the private source/alignment stage of its first release. The cgroup memory-failure count remains 14 (no new failures since the compiler correction). Mac K3 retry is in secure PSI comparison; no topology release is counted yet.

## 2026-09-18T18:58Z — resumed integration; fused alignment projection verified

Targeted commands: `testthat::test_local(filter="^dp-alignment-mask$|^dp-glm-grid-cross-contract$")` (server **376 assertions, zero failures/errors**), client corresponding alignment-transport/grid-contract filter (**375**, zero failures/errors). New server test first exposed two fixture errors (unattached source contract and environment assignment), both corrected; final logs are `fused-alignment-targeted.log` in each package. Grid-only authenticated source reads now require the matching digest-gate terminal and admitted typed artifact; older/mixed families retain the previous path. See DECISIONS_V2.

Stopped only the owned pod validation tree rooted at PID496594 (six processes) before any n2000 DP release; prepass log archived as `validation-binomial-e1-before-fused-alignment.log`. Restart uses the verified specialization. Mac K3 reached PSI completion but failed before custodial signatures; a four-row synthetic diagnostic is running to isolate admission without repeating full PSI. Required 120/12 evidence and topology gates remain NOT DONE.

## 2026-09-18T19:07Z — K3 real diagnostic PASS; session and fixture fixes

`relay-admission-targeted.log`: **272 assertions pass**, zero failures/errors (Synopsis authorization, DSLite session binding and complete endpoint inventory). A broader security-filter run also exposed pre-existing inventory gaps and source-tree temporary-artifact contamination; its results are retained separately and are not claimed as a clean full suite.

`topology-k3-small.log`: real n4/p6/grid2/K3 binomial epsilon4 API release **126.471 s**, complete integer DP vector equals independently planned production-noise oracle bit for bit. This diagnostic is not one of the twelve n2000 releases. It establishes the authorization-field compatibility fix and fused digest route across three owners.

Pod campaign restarted PID **572347** after removing the incompatible session field; its first n2000 PSI is complete. Mac full topology campaign restarted (native exec session **66240**) after correcting ten-predictor public radix ordering (`topology-public-order.log`). The previous large attempt's generic rejection is preserved in `topology-binomial-k3-before-authorization.log`; subsequent pure-public inspection identified the ordering cause. No failed/interrupted attempt is counted as a release.

## 2026-09-18T19:08Z — broader targeted security run classified

`relay-authorization-targeted.log` completed with three failures: one obsolete synthetic debug RDS under the ignored development build directory, a test treating empty `.Rbuildignore` lines as match-all patterns, and missing endpoint inventory entries. The inventory regression now passes (272-assertion targeted run above). Removed only the obsolete task-owned debug snapshot and empty build-ignore lines, then reran the package-artifact test. No security-profile or authorization assertion failed in the broader run. Full clean-source package suites remain pending on the pod.

Package-artifact rerun: **5 assertions pass**, zero failures/errors (`package-artifact-targeted.log`). Final-check input manifest refreshed to **1494 files**, now also hashing client installed resources and package configure/binary inventories.

## 2026-09-18T19:14Z — typed-worker startup retry

Pod first n2000 release reached typed START then failed with the constant readiness error; no DP vector was released and the memory-failure count did not rise. Archived log: `validation-binomial-e1-before-grid-readiness.log` on the pod. The larger typed circuit was still subject to the generic five-second readiness window. Scoped grid-only wait is now 120 seconds; **60 pair-binding/readiness assertions pass** (`grid-readiness-targeted.log`). No worker binary, cap or arithmetic changed.

Restarted only owned validation: pod PID **594902**, Mac topology native exec session **11071**. All release matrices remain pending; failed attempts are not counted. The package-check snapshot will be updated with this one R file before full checks.

## 2026-09-18T19:17Z — full-envelope public admission verified cheaply

Client `testthat::test_local(filter="^dp-glm-grid-cross-contract$")`: **319 assertions pass**, zero failures/errors (`full-envelope-admission.log`). The new pure-R cases authenticate three-owner n10000/p10/grid50 contracts for both certified families and reject noncanonical predictor order. The fixture initially omitted the newly participating owner's patient-key declaration; adding that signed public declaration corrected the fixture. No validator was weakened. Client commit `b30631f`; final-check manifest refreshed for this test and the scoped readiness fix.

## 2026-09-18T19:27Z — larger typed startup passes; K3 full envelope admitted

The n2000 pod retry has persisted its first grid batch on **both** authorities, confirming that the scoped readiness window permits actual larger typed-worker startup. This is progress within the first required release, not a completed DP release. Mac K3 n10000/p10/grid50 now passes real PSI, custodial signatures and public admission with the corrected canonical fixture; secure execution follows. Source/runtime remains frozen at server `83c7e66` (later commits add only evidence/tests) and client runtime `1acfd0c`.

## 2026-09-18T19:35Z — bound admission reuse verified; campaigns restarted

`bound-admission-targeted.log`: **292 assertions pass**, zero failures/errors. Full authentication remains mandatory at bind; subsequent lifecycle stages require the identical validated public request tuple and bound context. The previous n2000 attempt had persisted multiple matching batches but had not released a DP vector. Its log is archived as `validation-binomial-e1-before-bound-admission.log` on the pod; the K3 admission-only log is retained locally. Both are excluded from required release counts.

Stopped only owned validation trees and the still-waiting full-check runner (PID620527; no full suite started). Restarted pod campaign PID **640037**, Mac topology native exec session **39769**. Benchmark lane continues unchanged. The refreshed source will be hashed into the final-check archive before requeuing full checks.

## 2026-09-18T19:40Z — final suites queued on verified frozen inputs

All 1494 hashes in `final-check-inputs.sha256` match the private POSIX pod archive after bound-admission changes. Full-check runner PID **646223** waits for the benchmark matrix's completion marker before starting the one full Go suite and both `R CMD check --no-manual` runs. Neither full suite has started yet. Runtime server source is `6fd6194`, client runtime `1acfd0c`; test/package inputs include client `b30631f` and the current manifest commit `0b053a7`. Current pod validation PID640037 has completed PSI; current Mac topology session39769 remains in PSI. No completed required release is yet claimed.

## 2026-09-18T20:11Z — public-circuit cache verified and deployed

`circuit-cache-worker-targeted.log`: **10 Go test/subtest results pass**, including authenticated cache reuse and actual two-peer oracle equality for both families. `circuit-cache-server-targeted.log`: **352 R assertions pass**, zero failures/errors. `circuit-cache-reproducible.log`: all four rebuilt artifacts verify; pod hashes exactly match local `inst/bin/SHA256SUMS`. New Linux SHA-256: `cb556efb40e4cf4a6e3fb984e494da4e7c0946e70b131d9ee8dbaffdbf166d3f`.

Previous n2000 baseline reached at least 15 matching durable batches but no completed DP release. Archived pod log `validation-binomial-e1-before-circuit-cache.log`; Mac pre-cache admission log is retained. Only owned validation trees were stopped. Current pod runner PID **712021**, Mac topology native exec session **41282**, use the authenticated public-circuit cache and existing 8 MiB relay window. One brief Mac startup was restarted before PSI to include warning suppression on private cache-directory creation. Full-check waiter PID646223 was stopped before any full suite began; snapshot refresh follows this deployment.

Benchmark matrix continues on its original frozen worker: additional full n10000/p5/grid50 measurements pass, binomial **75,062,442,900 bytes / 1659.673 s**, Poisson **95,310,355,319 bytes / 1905.672 s**. Required n10000/p10/grid50 measurements already passed as recorded above. Required 120/12 and K3/K5 releases remain NOT DONE; no interrupted attempt is counted.

## 2026-09-18T20:16Z — resumed; relay-window correction

Both campaign attempts rejected the experimental 8 MiB window before admission with `dsvert_resource_oversize:v1`. This repeats the earlier documented transport constraint: the configurable worker ceiling does not imply compatibility with the fixed DataSHIELD expression limit. Restored the default 480 KiB window; no resource ceiling changed. Authenticated circuit caching remains enabled and verified. Failed attempts are archived and count as zero releases. Repositories were inspected before resuming; only campaign output files were untracked.

## 2026-09-18T20:18Z — both benchmark matrices complete

Pod `MATRIX_POD_DONE`; `summarize_bench.py` validates all 16 distinct cells, integer/DP-oracle equality, and full-envelope byte/time gates. Mac matrix also has 16/16 completed cells. Full-envelope pod: binomial 86,515,842,839 bytes / 2795.701 s; Poisson 106,763,755,314 bytes / 2695.032 s. Both pass 110 GB / 4 h; both exceed the original 30-minute reporting threshold. Scope excludes DataSHIELD framing and catalog count, explicitly stated in BENCH_V2.md.

Restored-window validation runners: pod PID717883, Mac native session94315. Final-check runner PID718889 now has the completed benchmark marker and verified 1496-file source archive. Required release matrix remains in progress.

## 2026-09-18T20:28Z — full checks active; inventory correction

Full Go suite and server R CMD check started from the frozen archive. Server static/documentation/example checks passed; testthat found the new endpoint missing from `remote_surface_classification.json`. Corrected only that inventory entry and its count; targeted `test-aggregate-surface.R` passes **145 assertions** (`remote-inventory-targeted.log`). Retain the running check unchanged for complete failure accounting; the corrected package requires a follow-up check. Validation has persisted two matching kernel batches on both authorities; no completed required release yet.

## 2026-09-18T20:30Z — client full check started

`R CMD check --no-manual dsVertClient_1.2.1.tar.gz` is running on the pod as PID739243. Corrected the reproduction runner to derive archive versions from DESCRIPTION; the client version 1.2.1 was already present and is unchanged. Server testthat and Go full suite continue on their original frozen archive.

## 2026-09-18T20:36Z — three full-check fixture failures reproduced and corrected

`check-fixtures-targeted.log`: **468 assertions pass** after source-path and alignment-mock corrections. The original pod check errors are reproduced in `check-failures-targeted.log` (to collect after final checks). An additional Synopsis artifact failure is being isolated: its standalone local test passes 57 assertions. Production validation continues with 13 matching durable batches on each n2000 authority; no final DP vector yet.

## 2026-09-18T20:46Z — client full-suite result and targeted corrections

Client R CMD check completed: **25,476 PASS / 4 FAIL / 45 SKIP**, testthat warnings 0; package check has 1 ERROR and 3 WARNING categories. Failures are missing shared inventory/explicit retry entries for the new route; corrected targeted audit passes **99 assertions** (`dsVertClient/inst/cross-grid-v2/check-inventories-targeted.log`). Two stale transport Rd files are regenerated. Two pre-existing packaging warnings await a narrowly scoped user decision; patch is prepared. Full server and Go suites remain running.

## 2026-09-18T20:50Z — real transport regression rerun passes

Two previously failing transport tests now pass **1213 assertions** with `NOT_CRAN=true`, after fixture metadata corrections only. Installed namespace-audit corrections are passing on the pod; the remaining START cases are still running. First client check/test logs are retained as `check-client-first.log` and `check-client-tests-first.log`. The n2000 production campaign passed 32 matching batch records per authority; no completed required DP release yet. Pod memory use ~11.8 GB; prior memory-failure counter remains 14 (unchanged).

## 2026-09-18T20:55Z — installed regressions pass; concurrent campaigns active

`synopsis-installed-corrected-targeted.log`: **531 assertions pass**, zero failures/skips in the six corrected installed-layout Synopsis files. Server and Go full suites continue on their unchanged original archive. New pod scheduler PID829845 adopts existing n2000/binomial/epsilon1 PID718153, starts binomial/epsilon4 and Poisson/epsilon1, then fills the remaining cells. Mac scheduler native session29849 adopts K3/binomial PID22057 and starts K3/Poisson; K5 follows each family. Old waiting shells only were terminated; no live R release or MPC worker was stopped. Reproduction/adoption scripts are committed; required completed-release counts remain zero until final equality markers.
