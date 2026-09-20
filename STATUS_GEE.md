# Fixed working-correlation GEE status — 2026-09-20

**PENDING real release proof. Neither GEE family is promoted at this checkpoint.**
The accepted target is binomial and Poisson GEE with analyst-specified fixed
working correlation. The pending gates below require retained evidence from
this isolated lane; a contract change or a focused test pass does not fill them.

## Source and isolation

Both repositories use branch `gee-fixed-rho` under
`/Users/david/Documents/GitHub/dsvert-gee/`. The exact committed bases are:

| Repository | Base commit |
|---|---|
| dsVert | `2146bf158abb68951dab0e4f96f4bcbca311ee91` |
| dsVertClient | `4c6c5622fbdc2ae97de315f18c18901d452f3c09` |

The implementation is committed separately from those bases:

| Repository | Implementation commit |
|---|---|
| dsVert | `902ccf46d0f9b844155ff4316ac91cac2a2ba75b` |
| dsVertClient | `6d94d4c9e15b9261a31b4499837d200ea1caea17` |

The current proof snapshot is `/workspace/dsvert/gee-fixed-rho-r7`, from server
commit `74a408fcb42b30916460c54975449f43fcde49a8` and client commit
`20adcc8cd237abba5aee6f58d941d7b2eebab77e`. It was exported from committed Git
objects with no dirty overlay; archive SHA256 is
`453d03331d903286810c3f1dc3a56a93c5c4f262250ad2578c7c4120c6159001`.
Its 2,621-file frozen manifest SHA256 is
`a57e599d16f284612554484ad041f1a43f03a5149eaa040435131e8d13a9294d`.
Both r7 builds passed. Native evidence reuses the 25 passing r6 GEE tests only
after all 614 native inputs, the rebuilt runtime and trusted r6 evidence hashes
matched. Fresh r7 focused R tests passed 953 assertions with zero failures,
errors, skips or warnings. The immutable r6 snapshot is
retained as failed release evidence. Exact build hashes are recorded
in [PROMOTION_GEE_FIXED_RHO.md](PROMOTION_GEE_FIXED_RHO.md). Build and proof use
this lane's own `/workspace/dsvert/gee-*` snapshots on pod4. The
integrator worktrees and frozen LMM jobs are not this lane's execution targets.

## Accepted scope and unchanged contract

- Families: `binomial_gee`, `poisson_gee`; composition `staged_fixed_rho_v1`;
  signed correlation contract `signed-analyst-fixed-rho-v1`.
- Independence rho=0 is the plug-and-play default. Exchangeable and AR1 remain
  options with rho in {0,1/4,1/2}.
  Rho is analyst-specified, data-independent and candidate-independent.
- The v3 whitening producer, likelihood, bread and clipped-score meat use the
  existing exact OT products and profile `grouped-gee-whitening-f96-q64-v3`.
  The full released vector includes every candidate and both upper triangles.
- The arithmetic domain is B<=8 original slots, p<=3 covariates plus an
  intercept, J<=4 beta candidates, |eta|<=4, output grid bits 8..18, binary
  outcomes or Poisson outcomes in {0,...,4}, and quarter-step score clip
  in [.25,4]. This is not a measured release-capacity claim.
- The requested real proof cell is **n2000/C500/B4/p3/J2**, epsilon=8,
  delta=2^-100, grid bits=16, score clip=1, at K=2,3,5 authenticated source
  owners with two compute/noise authorities. The requested default correlation
  cell is independence rho=0. It has 42 GEE coordinates plus the count, within
  the unchanged 51-coordinate sampler limit. A successful default-cell release
  does not measure every retained rho/correlation or the larger J4 domain.
  Any eventual capacity claim is restricted to p<=3/C<=500 at B4/J2 and this
  default cell; no n2000 capacity measurement has passed yet.
- Signed per-coordinate caps, sensitivity calculation, epsilon/delta and runner
  caps are unchanged. Existing source/input/gate caps remain 2,097,152 bytes,
  524,288 bits and 32,000,000 gates. The release acceptance gate remains
  256,000,000,000 serialized aggregate RPC bytes and 21,600 seconds. The existing
  900-second idle/86,400-second execution lease does not extend that gate.
- Patient add/remove affects one bounded cluster vector; replacement/movement
  affects at most two. For coordinate caps L_k, the complete-vector bounds are
  m*sum(L_k) and m*sqrt(sum(L_k^2)), with m=1 or 2 and outward rounding of L2.
  Public cluster capacity multiplies coordinate maxima, not sensitivity.
- New attempts require fresh cryptography; recovery and replay retain the
  authenticated sticky release identity. No noise reseeding or privacy-budget
  reset is authorized by this scope change.

Both R packages bind certificate SHA256
`82df4b2c32f19f0ac248acbd424f079edd5e29546f95e6e3c520c2e2232be3e3`.
See [NUMERIC_CERTIFICATE_GEE_WHITENING.md](NUMERIC_CERTIFICATE_GEE_WHITENING.md)
for the arithmetic and patient sensitivity proof. Its arithmetic-only promotion
flags remain false; release promotion requires separate evidence.

## Evidence checkpoint

| Gate | Binomial GEE | Poisson GEE |
|---|---|---|
| Local R contract/admission sanity | PASS, shared 254 server +272 client assertions | Same focused run |
| Local r7 scheduling and adjacent regressions | PASS: 623 assertions across server/client files | Same combined runs |
| Frozen pod build and focused native/R/integer-oracle tests | PASS r7: 25 native via verified reuse + 953 fresh focused R; zero failures/errors/skips/warnings | Same combined runs |
| Explicit full transport, lease and publication regression files | PASS r7: 1,740 assertions; zero failures/errors/skips/warnings | Same combined run |
| r6 n4 independence-rho0 real DP preflight | FAILED during first DP sampler chunk; exit 1 | NOT RUN after binomial gate failed |
| r7 n4 independence-rho0 real DP preflight | RUNNING; no completed release | PENDING |
| Real n2000 epsilon8 K2 release and bitwise oracle equality | PENDING | PENDING |
| Real n2000 epsilon8 K3 release and bitwise oracle equality | PENDING | PENDING |
| Real n2000 epsilon8 K5 release and bitwise oracle equality | PENDING | PENDING |
| Recovery with fresh attempt cryptography and sticky identity | PENDING | PENDING |
| Tamper rejection and authenticated cold replay | PENDING | PENDING |
| Full paired server/client suites, warnings/skips reviewed | PENDING | PENDING |
| One measured capacity envelope at the stated proof cell | PENDING | PENDING |

The local counts are combined across both families, not per-family totals, and
contain zero failures/errors/skips. Local logs are retained under
[`inst/cross-grid-v2/gee-fixed-rho/evidence/local`](inst/cross-grid-v2/gee-fixed-rho/evidence/local):
`gee-server-contract-local.log`, `gee-client-contract-artifact-local.log` and
`gee-server-admission-local-r2.log`.
These checks do not substitute for pod or real release evidence. The pod driver
records process status, exact frozen source hashes, marker checks, measured RPC
bytes and first-publication elapsed time; incomplete jobs cannot pass.

The frozen dev-r3 pod run passed all 25 top-level native GEE tests in 348.931
seconds package time (380.908 seconds controller time), plus 629 server and 272
client focused R assertions with zero failures, errors, skips or warnings. Its
runtime and tagged integer-oracle builds both exited zero. Raw public records
are retained under
[`evidence/dev-r3`](inst/cross-grid-v2/gee-fixed-rho/evidence/dev-r3), including
the exact dirty-overlay source manifest and per-file `SHA256SUMS`. The dev-r3
focused proof covers the optimized public-program reuse and source-validity
conjunction; it does not establish n2000 release capacity.

The committed r4 snapshot's focused R recheck passed 629 server plus 288 client
assertions, including the added GEE transport regression, with zero failures,
errors, skips or warnings. Its controller exited zero after 143.239673 seconds.
The initial launcher failed with a Python syntax error before executing R;
both that failed controller record and the successful relaunch evidence are
retained under [`evidence/r4`](inst/cross-grid-v2/gee-fixed-rho/evidence/r4).
The r4 binomial n4 smoke subsequently failed during DP exact exchange after
its GEE producer completed. The r4 Poisson n4 smoke also failed, after RESULT
but before publication, as diagnosed below. The r4 server paired suite passed
22,532 assertions with zero failures/errors/skips/warnings in 3,975.800968
seconds, finishing at 09:10:42 UTC; its client suite is still pending. Neither
partial paired evidence nor failed releases fill the outstanding gates.

## r1 smoke failure and r2 source-materialization correction

Both n4 epsilon8/p3/J2/exchangeable-rho1/4 r1 smokes reached signed public
admission but failed before the GEE protected source computation and DP release.
The terminal error was `The requested numeric variable has no custodian-owned
bounds`. The ordinary local materializer omitted the two GEE artifact versions
from its cross-owner lists and attempted a local numeric-statistic path.

The correction adds only the two GEE versions to the existing cross-input
recognition and zero-release-block branches in `R/dpCapsuleMaterializer.R`.
The GEE regression fixture exercises both authorities and all three additional
K5 source owners, asserting that ordinary materialization contributes zero to
every GEE release coordinate without reading any outcome or covariate column.
The r2 n4 smokes subsequently failed in client operation admission as recorded
below. Neither failed revision supplies a promotion or capacity cell.

The Gaussian planner's `fixed-work Gaussian table is outside the certified
support` diagnostic was an unsuccessful optional planner probe. The retained
selector already catches it and selects its certified discrete-Laplace
fallback at the unchanged epsilon/delta and caps. Public-input checks confirmed
that fallback for both families at the retained q16 scope. No mechanism, sampler
support, output grid, sensitivity or cap change is required for this correction.

## r2 client operation-admission correction

The r2 n4 signed smoke progressed past source materialization and the staged
server preparation call, then failed in the client with
`Invalid exact MPC operation contract.` The client exact-transport operation
allowlist and expected output kind omitted `grouped-gee-fixed-rho-staged-v1`.
The correction adds that operation to the existing admission, Ring128/q0 and
purpose-binding guards, and binds its GEE-specific terminal kind. No shared
transport limits or other family behavior are changed.

The new GEE transport regression reproduced the exact error before the fix.
Afterward it passes 16 assertions, including successful 42-coordinate transport
orchestration and rejection of wrong rings, fractional scales, purposes,
estimated-alpha operation names, output kinds and changed candidate shapes.
The complete existing exact-transport test file also passes. Retained before/
after logs are in `inst/cross-grid-v2/gee-fixed-rho/evidence/local/` as
`gee-client-transport-before.log` and `gee-client-transport-after.log`.
Real release evidence remains pending for the next frozen source snapshot.

The two r2 n4 smokes both exited 1 before release, with all oracle/replay markers
false and `proof_passed:false`. Their raw public driver logs, launch records,
resource summaries, exits and source identity are retained under
[`evidence/dev-r2`](inst/cross-grid-v2/gee-fixed-rho/evidence/dev-r2), with
per-file `SHA256SUMS`. These evidence copies exclude private state, source
stores, seed files, RDS objects and executables.

## Historical r4/r5 attempts and failed publication

Pod4 SSH at `194.68.245.69:22043` began timing out/resetting connections around
08:23 UTC and was restored at 08:28 UTC. No restart, endpoint edit or intervention
in another owner's job was attempted. The old eight-job waiter, PID `2478097`,
was confirmed cancelled at **08:28:26 UTC before any n2000 launch**.

Both n4 native GEE producers completed before the sampler failures were
investigated. The r4 binomial n4 smoke exited 1 during `exactGCExchangeDS` after
`dsvertDPSynopsisStartDS`, in the first 36-coordinate discrete-Laplace sampler
chunk. Its controller wall time was 1272.70 seconds, R elapsed time 1161 seconds,
and peak child RSS 11,830,076 KiB. No result or release was recorded. The abort
removed the private worker logs, and the old main failure handler omitted its
captured worker error, so the underlying cause was lost.

The container memory limit was approximately 50 GB and its recorded maximum
reached that limit. The cumulative counters were `oom_kill=7` and `failcnt=66`,
but available records did not timestamp those events. **OOM is unproven for this
failure.** The r4 Poisson n4 controller exited 1 at 09:09:08 UTC after
3,881.587476 seconds, with peak child RSS 22,291,268 KiB. Its RESULT phase
completed, but both authorities rejected RELEASE with
`Invalid typed-blob synopsis geometry or route.` All oracle/replay markers
were false. This is a distinct, verified publication failure, not evidence
about the cause of binomial's earlier sampler failure.

The local GEE diagnostic patch now includes the captured operation/error
message and available worker exit status in main/recovery failure reports.
The campaign schedules one release at a time, with two authorities per release,
as a resource mitigation. All privacy, numeric, transport and acceptance caps
remain unchanged. No 8 MiB transport-chunk change was made: the retained client
DSI expression cap is 786,431 bytes.

Both historical exchangeable-rho1/4 n2000 integer commitments were complete
and source-verified:
binomial `6226c79ddfccb4068a41e91056f13a5bf1c24753e9a0581c716d0d108f6e6feb`,
Poisson `b245f22eaced4faa21b2c2e05ac13f4d3ff5f05616f5b72a4744a91879ec2821`.
These are plaintext synthetic oracle commitments, not authenticated DP releases,
and cannot be reused for the new independence-rho0 proof cell. The six-job
schedule remains one publication per family/topology: K2 includes recovery,
K3 supplies the ordinary capacity measurement, and K5 supplies the remaining
topology proof. Fresh independence oracle commitments and a source-bound
manifest are now retained in the r6 evidence update below; `promoted:false` remains.

[CHECKPOINT_GEE.json](inst/cross-grid-v2/gee-fixed-rho/CHECKPOINT_GEE.json)
records exact own-job PIDs, snapshot paths, evidence bindings and continuation
steps. The r5 continuation launched at **08:53:43 UTC**, PID `2610081`, with
stdin `/dev/null`. Its controller SHA256 is
`9964c40d890a07f8ea575476390c33ff1b5f7ddb03f85a8fb4f0cd9e3591b985`.
Fresh r5 focused R tests passed at **08:55:42 UTC** in 113.309429 seconds:
629 server plus 288 client assertions, zero failures/errors/skips/warnings,
with frozen-source verification passing. That continuation waited for the
r4 Poisson and paired controllers. Paired-source comparison
found only the standalone GEE failure-diagnostic harness changed across all
R/Go/certificate/runtime inputs; package code and tests are identical.

The r5 continuation PID `2610081` was explicitly cancelled at **09:10:53 UTC**
before any n2000 launch; its four retained public records are in
[`evidence/r5-cancelled`](inst/cross-grid-v2/gee-fixed-rho/evidence/r5-cancelled),
with `SHA256SUMS` digest
`70e42b31ac7878d43aa787743ac3377db1d4a38900c3c060ee08a57788604b25`.
The ten-file r4 final evidence set is in
[`evidence/r4-final`](inst/cross-grid-v2/gee-fixed-rho/evidence/r4-final),
with `SHA256SUMS` digest
`6e3046518979dadde81e0b9bc47f0862543f1b6b67408526adc40b1de8725832`.
The r5 controller does not own the current campaign. The r4 suite is
historical evidence: r6 changes package transport and publication code, so r4
cannot establish the full paired gate for r6.

## r6 corrections, passed tests and failed DP preflight

The immutable r6 snapshot binds server
`9b6c1a18de6b1b68a1ef6832991ece1ea680eb9a`, client
`6d94d4c9e15b9261a31b4499837d200ea1caea17` and frozen manifest
`d41a66b168b424e78da3134eb14462e24cb4b5454981ec8c20f18b852500201c`.
Its tagged oracle SHA256 is
`1deee926d09fb3caf0022a41821533040cce9c6b29ccb9bd9afde557ebc4a900`.

The Poisson failure exposed a mismatch between two existing contracts. The
authorized exact sampler plan selected 36-coordinate execution chunks for the
43-coordinate publication, while typed FINAL_SHARE validation required the
full `min(64,total)=43` width. The corrected structural validator accepts
widths up to that ceiling. The authorized attempt still fixes the actual width,
and the release reader compares the complete expected context and segment
descriptors. A regression admits the real 43/36 geometry, rejects malformed
counts/routes and zero/over-limit widths, and rejects a coherently reshaped
22-coordinate payload against the authenticated 36-coordinate context.

A separate transport diagnostic correction preserves terminal worker failure
through lease checks until explicit abort and records its private failure
classification. It does not establish why the historical binomial sampler
failed, and does not establish OOM causation. The 900-second inactivity and
86,400-second total leases and the independent six-hour release gate are unchanged.
The GEE release lock enforces one release per DataSHIELD transport and one
concurrent release in this lane, including serial n4 preflights.

The r6 controller PID `2728246` started at **09:19:24 UTC**, detached with stdin
`/dev/null`. Its SHA256 is
`736a8f05d642234c71341bd5b342c10b333c400d16320123e2935d62fd320094`;
the source archive SHA256 is
`58a0a6471e98ba256494157c7798b7d9001b2f180cc55bea721e924d64e61937`.
Both builds and the 25 top-level native GEE tests exited zero. The native
package time was 347.120 seconds and controller time 377.775880 seconds.
Focused R and full exact-transport, session-lease and typed-downstream tests
also passed. Both n2000 independence commitments are complete and source-bound.
The binomial n4 preflight failed with controller exit 1 after 994.257451
seconds (895.1 seconds R elapsed; peak child RSS 22,097,240 KiB). The captured
`joint-dp-vector-laplace-v3` worker failure was `infrastructure_unavailable`,
with worker exit status -9. All oracle/replay markers were false. The container
`oom_kill` counter rose from 7 before the attempt to 8 afterward. Combined
with the killed worker, this is strongly consistent with memory pressure;
available kernel records do not attribute the OOM event to that exact PID.

The failed gate stopped this controller before Poisson n4, either fresh paired
suite or any n2000 job could launch. The r6 snapshot, failed attempt and source
manifest remain immutable. **Neither family is promoted.** The failed smoke
does not measure n2000 capacity or validate the publication correction in a
successful end-to-end release.

## Current r7 scheduling correction and proof controller

The r7 change is implemented and tested locally; real release proof is still
pending. It schedules authenticated GEE execution in 16/16/11-coordinate chunks for
the complete 43-coordinate vector while retaining the same global sampler
plan, sensitivity, privacy parameters and caps. The changed geometry affects
the authenticated attempt, transcript and noise derivation, so r7 requires a
fresh synthetic proof identity. It must not migrate or resume r6 private state
or be counted as recovery of the failed r6 attempt. Local server scheduling/
publication tests passed 172 assertions, adjacent execution tests passed 324,
and client scheduling/adapter tests passed 127: **623 assertions total**.
Logs are retained under `evidence/local` as `gee-fixed16-server-after.log`,
`gee-fixed16-server-adjacent.log` and `sampler-fixed16-client-green-20260920.log`.

The r7 controller PID `2957748` launched at **10:10:10 UTC**, detached with stdin
`/dev/null`; controller SHA256 is
`beb9afcce8d4f26f08abd1b7fcbb5a571a4bb3b384624c30906543f65689efc8`.
The runtime build exited zero in 11.630928 seconds and the tagged oracle build
in 30.971193 seconds. Native reuse pins r6 manifest
`d41a66b168b424e78da3134eb14462e24cb4b5454981ec8c20f18b852500201c`,
its native log/exit hashes, all 614 native inputs and the rebuilt runtime hash.
The tagged oracle was rebuilt in r7 and retains its own new hash. The four
synthetic oracle JSON records may be reused only after their trusted hashes
and all source dependencies match; this does not reuse a private release.

Fresh r7 focused R tests passed **629 server +324 client =953 assertions**
with zero failures/errors/skips/warnings at **10:13:13 UTC**, after 121.015181
seconds. The full transport/publication regressions passed 37 cases and 1,740
assertions with zero failures/errors/skips/warnings at **10:17:06 UTC**, after
223.732419 seconds. The binomial n4 real
preflight launched at **10:17:15 UTC**, controller PID `2995126`, with stdin
`/dev/null` and the required 900-second inactivity/86,400-second total leases.
It remains active without a completed DP release. Poisson n4, both fresh full
paired suites and all six n2000 jobs remain pending. Real release, recovery,
tamper and capacity gates are unfilled; the active preflight does not establish
that memory pressure or publication is resolved.

The [retained r7 evidence](inst/cross-grid-v2/gee-fixed-rho/evidence/r7)
contains 27 public files; `SHA256SUMS` SHA256 is
`3c584a3e93b4fcf60c6d76997be74c6897d69ec3d150635d6aeb937d885e01d0`.
The derived `focused-proof.json` SHA256 is
`4723ff7d9ffbb58b0823262b5b4d4db2b6dedd033f41360c4eaf8418ecb348cd`.
These are build, focused and transport evidence, not a completed DP release.

The [capacity observation note](inst/cross-grid-v2/gee-fixed-rho/evidence/local/capacity-observation-20260920.md)
records active relay throughput and repeated n4 stage timing. Multiplying its
approximately 412-second cluster block by 500 gives a roughly **57-hour warning
projection**, not an n2000 measurement, completion forecast or lower bound.
The six-hour acceptance gate and all other caps remain unchanged; the projection
does not fill a capacity result.

## Estimated correlation boundary

The implementation coefficient alpha=(1-rho)^(-1/2) is not an estimate. A
private shared correlation estimate can change every cluster contribution
when one patient changes. Keeping it private does not preserve the fixed-rho
bound; the generic bound can grow by C500, destroying utility at unchanged
noise-budget parameters. Estimated correlation remains future work requiring
an explicit estimator and a bounded whole-vector sensitivity proof or an
accounted privacy mechanism. No estimated-alpha claim is made here.

## Handoff

The exact shared-file integration list, build-output exclusions, evidence cells
and pending sign-off are recorded in
[PROMOTION_GEE_FIXED_RHO.md](PROMOTION_GEE_FIXED_RHO.md). The two family rows in
[release-manifest-rows.json](inst/cross-grid-v2/gee-fixed-rho/release-manifest-rows.json)
remain `promoted:false` until those gates pass. No push, tag or thesis edit is
part of this lane.

## Retained r6 focused, oracle and failed release evidence

The frozen r6 build passed all 25 native tests, 629 server plus 288 client
focused R assertions, and all 1,697 assertions in the full exact-transport,
lease and typed-publication regression files. All exited zero with no failures,
errors, skips or warnings. [Retained r6 evidence](inst/cross-grid-v2/gee-fixed-rho/evidence/r6)
contains 38 public files, including the failed binomial log/resources/launch/
exit records and final continuation state. Its `SHA256SUMS` digest is
`730730faaed93525deb3375d6c54c35cfea8a57cc579afaf45111161d728e755`.

Fresh independence-rho0 n2000 exact commitments are binomial
`623653b980fefa7b7b42a599ffe5ee4fea52465324f55fd047e7c9383c5c500d`
and Poisson `3b4cce7f7b713a1f1801e6965821753012865d3d84590b97b8023c3fff7be858`.
The generator verified their exact integers, program hashes and every oracle
dependency against frozen r6. Historical exchangeable commitments remain in
`oracle-commitments/exchangeable-rho0.25/`; they were not relabeled. The r6
campaign never launched; its preflight failure cannot establish r7 release
evidence. The current six planned rows and both family summaries bind the
verified independence commitments and frozen r7 source, with
`fleet_ready:false` and `promoted:false` until their respective gates pass.
Neither family has a completed r6 DP release or any n2000 release evidence.

## r7 live sampler checkpoint — 10:36:20 UTC

The binomial n4 producer completed all 25 stages per authority. Its first
16-coordinate DP sampler workers, PIDs `3056954` and `3057008`, remain alive
with fresh heartbeats and no error/abort markers. Sender acknowledgement
advanced from 70,287,432 to 115,015,752 raw protocol bytes in 105 seconds;
these are not serialized release RPC metrics. Observed worker high-water marks
are 5,589,256 and 4,988,628 KiB, and sampled container use peaked at
19,643,416,576 bytes against the 49,999,998,976-byte limit. The OOM counter
remains 8. This is partial first-chunk evidence, not proof that every chunk
fits, a completed publication, or measured n2000 capacity.

Seven public checkpoint copies are retained in
[`evidence/r7-progress`](inst/cross-grid-v2/gee-fixed-rho/evidence/r7-progress),
with `SHA256SUMS` digest
`861ee5b273357fb16f7624e5eb4786badb3cfbf8bb8140b10dd6607659185f6f`. The detached controller remains
active; Poisson n4, both fresh paired suites and all six n2000 jobs are still
gated. Both families remain unpromoted.

At 10:39:52 UTC, read-only queries of allowlisted integer metadata showed
three planned execution chunks and START records for indices 0 and 1 on both
authorities. Both publication counts were zero. No record JSON, shares, seeds,
payloads, keys or row MACs were read. This confirms advancement to the second
sampler chunk; full release proof remains pending.
