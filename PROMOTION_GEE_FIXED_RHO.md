# Fixed working-correlation GEE promotion record

**Decision: PENDING. No real release or capacity promotion is asserted.**

Accepted statistical scope: binomial and Poisson GEE with signed,
analyst-specified fixed rho. Independence rho=0 is the plug-and-play default;
exchangeable and AR1 remain options with rho in {0,1/4,1/2}.
The v3 whitening alpha is a fixed coefficient, not an
estimated correlation. The accepted fixed scope supersedes the request to
estimate alpha for this promotion; it does not establish estimated-alpha GEE.

## Source binding

| Item | Value |
|---|---|
| Branch in both isolated worktrees | `gee-fixed-rho` |
| Server base commit | `2146bf158abb68951dab0e4f96f4bcbca311ee91` |
| Client base commit | `4c6c5622fbdc2ae97de315f18c18901d452f3c09` |
| Server implementation commit | `902ccf46d0f9b844155ff4316ac91cac2a2ba75b` |
| Client implementation commit | `6d94d4c9e15b9261a31b4499837d200ea1caea17` |
| Current server proof-source commit | `74a408fcb42b30916460c54975449f43fcde49a8` |
| Current client proof-source commit | `20adcc8cd237abba5aee6f58d941d7b2eebab77e` |
| Current frozen pod snapshot | `/workspace/dsvert/gee-fixed-rho-r7` |
| Frozen r7 source manifest SHA256 | `a57e599d16f284612554484ad041f1a43f03a5149eaa040435131e8d13a9294d` |
| Committed Git archive SHA256; no dirty overlay | `453d03331d903286810c3f1dc3a56a93c5c4f262250ad2578c7c4120c6159001` |
| Rebuilt Linux amd64 runtime SHA256 | `a59e004567027fc0c09c620cf9ab8dcae0000efb4477f14672997fd800b150c6` |
| Rebuilt r7 tagged integer-oracle SHA256 | `3b6fa438856c989f97270c351e1dc0b9eec7fdfaf001ec8d892c090cf2f7d3f1` |
| Numeric certificate SHA256 | `82df4b2c32f19f0ac248acbd424f079edd5e29546f95e6e3c520c2e2232be3e3` |

The base commits precede the implementation commits above. Historical r4
evidence binds server `902ccf46` and the unchanged client. Historical r5 binds
server `a3964d39`; it reused dev-r3 binaries after all 614 native source inputs
matched. The failed r6 attempt binds server
`9b6c1a18de6b1b68a1ef6832991ece1ea680eb9a` and the original implementation
client `6d94d4c9e15b9261a31b4499837d200ea1caea17`, with
2,621 frozen files and no dirty overlay. Its runtime and tagged oracle were
rebuilt in this snapshot, both exiting zero in 14.000808 and 30.784327 seconds,
respectively. The dev-r3 source manifest SHA256 is
`cc108c3eb3881957c98534c4d65e73a6c6b09990018cde584db58bb95cdd0305`.
The r6 source archive SHA256 remains
`58a0a6471e98ba256494157c7798b7d9001b2f180cc55bea721e924d64e61937`.
Its manifest SHA256 remains
`d41a66b168b424e78da3134eb14462e24cb4b5454981ec8c20f18b852500201c`,
and its tagged oracle SHA256 remains
`1deee926d09fb3caf0022a41821533040cce9c6b29ccb9bd9afde557ebc4a900`.
The r6 binomial n4 DP preflight failed and stopped later release/paired gates;
that snapshot and evidence remain immutable. Current r7 has 2,621 frozen files
exported from committed objects, with fresh successful runtime/oracle builds
in 11.630928/30.971193 seconds. It reuses the 25 native r6 passes after matching
all 614 native inputs and the rebuilt runtime and pinning trusted r6
manifest/log/exit hashes. Fresh r7 focused R tests passed 953 assertions with
zero failures/errors/skips/warnings. Real release
and paired-suite proof remain pending. Detached jobs use
`< /dev/null` in the lane's own `/workspace/dsvert/gee-*` snapshots on pod4.
Do not rewrite a frozen manifest to make an already-running job match new code.

## Exact capacity and statistical scope

The arithmetic certificate admits p<=3 covariates, J<=4, B<=8 and the retained
fixed-correlation set. The requested real release proof is narrower:
**n2000/C500/B4/p3/J2**, epsilon=8, delta=2^-100, q16 output, score clip=1,
independence rho=0, K=2/3/5 source owners and two compute/noise authorities.
The count plus complete two-candidate likelihood/bread/meat vector has 43
coordinates. The existing 51-coordinate sampler cap is unchanged; p3/J4 would
require 85 coordinates and is not part of this capacity claim. Any eventual
measured capacity claim is restricted to p<=3/C<=500 at B4/J2 and the default
independence-rho0 cell. No n2000 capacity measurement has passed yet.

Signed coordinate caps, whole-vector patient sensitivity, epsilon/delta,
source/input/gate caps and runner limits remain unchanged. Acceptance requires
<=256,000,000,000 serialized aggregate RPC bytes and <=21,600 seconds for the
complete measured release. The measured RPC accounting excludes IPC framing;
report that limitation with the metrics. Record bootstrap-through-first-
publication elapsed time separately from oracle/replay/recovery process time.
The 900-second idle/86,400-second execution lease does not relax acceptance.

Add/remove changes one bounded cluster contribution; replacement/movement
changes at most two. The complete-vector L1/L2 bounds are independent of public
cluster capacity. A shared estimated rho can influence all 500 clusters and is
outside this proof; estimated correlation requires future estimator/privacy/
global-sensitivity work, with no utility or impossibility claim here.

## Required evidence and decision

Fill cells with retained artifact paths and SHA256 digests, actual exit status,
source identity and relevant measured quantities. Do not substitute a planned
command, source-only proof or synthetic noise simulation for a real release.

| Evidence | Binomial GEE | Poisson GEE |
|---|---|---|
| Local r7 scheduling and adjacent regressions | PASS: 623 assertions across server/client files | Same combined runs |
| Focused native/R/integer-oracle proof on the frozen pod build | PASS r7: 25 native via verified reuse + 953 fresh focused R; zero failures/errors/skips/warnings | Same combined runs |
| Explicit full transport, lease and publication regression files | PASS r7: 1,740 assertions; zero failures/errors/skips/warnings | Same combined run |
| r6 n4 independence-rho0 real DP preflight | FAILED during first DP sampler chunk; exit 1 | NOT RUN after binomial gate failed |
| r7 n4 independence-rho0 real DP preflight | RUNNING; no completed release | PENDING |
| K2 n2000 real epsilon=8 release, `DSLITE_ORACLE_BITWISE_EQUAL` | PENDING | PENDING |
| K3 n2000 real epsilon=8 release, `DSLITE_ORACLE_BITWISE_EQUAL` | PENDING | PENDING |
| K5 n2000 real epsilon=8 release, `DSLITE_ORACLE_BITWISE_EQUAL` | PENDING | PENDING |
| K2 recovery: fresh PREPARE/remasking, unilateral COMMIT replay, durable R handoff | PENDING | PENDING |
| Signed-contract/source/receipt tamper rejection and cold authenticated replay | PENDING | PENDING |
| Full paired server/client suite, failures/errors/warnings/skips reviewed | PENDING | PENDING |
| One measured capacity envelope at the declared n/p/J/C/B/rho scope | PENDING | PENDING |
| Reviewer decision and admitted measured scope | PENDING | PENDING |

The local R contract/admission checks passed 254 server and 272 client assertions,
combined across both families, with zero failures/errors/skips. This is fast
sanity evidence only; the retained logs are under
[`inst/cross-grid-v2/gee-fixed-rho/evidence/local`](inst/cross-grid-v2/gee-fixed-rho/evidence/local).
Pending rows remain `promoted:false`; release success at
the default correlation cell cannot establish unmeasured full-domain capacity.

The dev-r3 pod builds and focused proof all exited zero: 25 top-level native
GEE tests passed in 348.931 seconds package time (380.908 seconds controller
time), and the R/integer-oracle tests passed 629 server plus 272 client
assertions, with zero failures, errors, skips or warnings. These are combined
family counts. Raw public artifacts are retained below, with byte-preserving
copies verified against their snapshot hashes:

| Retained evidence | Identity or SHA256 |
|---|---|
| [dev-r2](inst/cross-grid-v2/gee-fixed-rho/evidence/dev-r2) failed n4 proof, 14 files | Source manifest `4a0397e52f762b832405923126179c9f56b0c1fd2dc931cb60c5c0afba58ae24` |
| [dev-r2/SHA256SUMS](inst/cross-grid-v2/gee-fixed-rho/evidence/dev-r2/SHA256SUMS) | `78cac612eda1d63c00421153703db3c77bdc2240e75800dba559f5dfcf5a76dd` |
| [dev-r3](inst/cross-grid-v2/gee-fixed-rho/evidence/dev-r3) build/focused proof, 15 files | Source manifest `cc108c3eb3881957c98534c4d65e73a6c6b09990018cde584db58bb95cdd0305` |
| [dev-r3/SHA256SUMS](inst/cross-grid-v2/gee-fixed-rho/evidence/dev-r3/SHA256SUMS) | `31f950e2347e921513d9e3f971040972fca88dbe869ff9e86d964fdd338f3f28` |
| dev-r3 `logs/gee-native-focused.log` | `4be87a0c3137699068bc36973a45ba64e72ded6548a6ba019c503d38e03c3554` |
| dev-r3 `logs/gee-r-focused.log` | `88486fddc7d85c2a7c738e6588bb58a5a256aa40b972715305f0ed4ea5d9c340` |
| [r4](inst/cross-grid-v2/gee-fixed-rho/evidence/r4) focused R proof, failed binomial n4 and waiter cancellation, 15 files | Source manifest `1d4b78e617c85b7874d0b56c09f03977e1606a1b0b60e8869d2126e5427934df` |
| [r4/SHA256SUMS](inst/cross-grid-v2/gee-fixed-rho/evidence/r4/SHA256SUMS) | `52ed2d2bc42ea263942512b928f3b5c359e1c0501d0e87c9c9390eb65593a30b` |
| r4 `logs/gee-r-focused.log` | `be0b1110033bdbbd7df95a3f436e66e4b3553474003bbc6498ae0715dd8957e5` |
| [r5](inst/cross-grid-v2/gee-fixed-rho/evidence/r5) frozen source/controller and focused R proof, 12 files | Source manifest `f6f7e9543975ffd0de441fce2c4259088f7446040fdfc1f9216cea7795cae6d0` |
| [r5/SHA256SUMS](inst/cross-grid-v2/gee-fixed-rho/evidence/r5/SHA256SUMS) | `212490d7ac25ea0d71f21558f683e6778a3496dcb806739fc68063b7f82f858a` |
| [r4-final/SHA256SUMS](inst/cross-grid-v2/gee-fixed-rho/evidence/r4-final/SHA256SUMS), 10 files | `6e3046518979dadde81e0b9bc47f0862543f1b6b67408526adc40b1de8725832` |
| [r5-cancelled/SHA256SUMS](inst/cross-grid-v2/gee-fixed-rho/evidence/r5-cancelled/SHA256SUMS), 4 files | `70e42b31ac7878d43aa787743ac3377db1d4a38900c3c060ee08a57788604b25` |
| [r6/SHA256SUMS](inst/cross-grid-v2/gee-fixed-rho/evidence/r6/SHA256SUMS), 38 files including failed binomial n4 | `730730faaed93525deb3375d6c54c35cfea8a57cc579afaf45111161d728e755` |
| [r7/SHA256SUMS](inst/cross-grid-v2/gee-fixed-rho/evidence/r7/SHA256SUMS), 27 public build/focused/transport files | `3c584a3e93b4fcf60c6d76997be74c6897d69ec3d150635d6aeb937d885e01d0` |
| [r7/focused-proof.json](inst/cross-grid-v2/gee-fixed-rho/evidence/r7/focused-proof.json), derived summary | `4723ff7d9ffbb58b0823262b5b4d4db2b6dedd033f41360c4eaf8418ecb348cd` |

The evidence copies include manifests, base-commit records and public build,
test and failed-smoke logs/status/metrics. They exclude private state, source
stores, seed files, RDS objects and executables. The committed r4 snapshot's R
recheck passed 629 server plus 288 client assertions, including the 16-assertion
GEE transport regression, with zero failures, errors, skips or warnings and
controller exit zero after 143.239673 seconds. Its initial launcher had a Python
syntax error before executing R; that failed controller log and successful
relaunch record are both retained. The r4 binomial n4 smoke subsequently exited
1 during DP exact exchange after the GEE producer completed: 1272.70 seconds
controller wall time, 1161 seconds R elapsed time and 11,830,076 KiB peak child
RSS. Its first 36-coordinate discrete-Laplace sampler chunk produced no stored
result or release. Cleanup removed the private worker logs, and the old failure
handler omitted the captured worker error; the underlying cause is unknown.
The failed binomial public log, launch record, resource summary and exit marker,
plus the confirmed waiter-cancellation record, are retained in the 15-file r4
evidence collection above. They document failure and cancellation, not release
or capacity success.
The r4 Poisson n4 controller exited 1 at 09:09:08 UTC after 3,881.587476
seconds, with peak child RSS 22,291,268 KiB. RESULT completed, then both
authorities rejected RELEASE with `Invalid typed-blob synopsis geometry or
route.` All oracle/replay markers were false. The r4 server paired suite
finished at 09:10:42 UTC with exit 0, 22,532 assertions, zero failures/errors/
skips/warnings and elapsed time 3,975.800968 seconds. Its client suite remains
pending. These final records are retained in `evidence/r4-final`; no n2000
release or measured capacity gate is filled.

The container's recorded memory maximum reached its approximately 50 GB limit;
cumulative `oom_kill=7` and `failcnt=66` have no available event timestamps.
These observations do not establish OOM as the binomial failure cause. The
local diagnostic patch preserves captured GEE operation/error messages and
available worker exit status in main/recovery failure reports. The new campaign
runs one release at a time to limit simultaneous sampler memory use, while
retaining two authorities and all existing epsilon/delta, numeric, transport
and acceptance caps. No 8 MiB chunk override was applied; the retained client
DSI expression cap is 786,431 bytes.

The r1 n4 signed smokes are failed pre-source evidence: ordinary local
materialization reported `The requested numeric variable has no custodian-owned
bounds` because its cross-owner version lists omitted GEE. The r2 correction in
`R/dpCapsuleMaterializer.R` restores zero local GEE release blocks. Both r2 n4
smokes subsequently exited 1 on the missing client exact-operation admission,
with `proof_passed:false`; the committed correction is recorded in
[STATUS_GEE.md](STATUS_GEE.md). An optional Gaussian-plan support rejection was caught by the
existing certified discrete-Laplace fallback and was not the terminal failure.
No sampler, mechanism-selection, grid, privacy budget or cap change was made.

The verified Poisson publication failure was caused by a structural validator
requiring `min(64,total)=43` execution coordinates, while the authenticated
physical plan required chunks of 36. The r6 correction accepts widths up to
the existing ceiling. The actual width remains bound by the authorized
attempt hash, durable execution state, the complete expected typed context
and exact segment descriptors. The regression admits the 43/36 geometry,
rejects malformed geometry/routes and zero/over-limit widths, and rejects a
coherent 22-coordinate segmentation against the original 36-coordinate context.

The r6 transport correction also preserves terminal `failed` status and its
private diagnostic through lease checks until explicit abort. This closes a
diagnostic loss path; it does not prove the historical binomial failure was
OOM. The 900-second inactivity and 86,400-second total leases remain unchanged.
The GEE lane lock enforces one release per DataSHIELD transport and one active
GEE release, including the n4 preflights, without changing other lanes.

## Shared integration files for the single-owner merge

This is the exact shared-file list from the current diff. Changes cover GEE
admission, dispatch, source bindings, certificate interpretation and validation,
plus the two shared transport/publication defects reached by the GEE release.
They do not refactor adjacent code.

| Repository/path | GEE change |
|---|---|
| `dsVert/R/crossgrid_grouped.R` | Fixed-correlation declaration, certificate binding and artifact token |
| `dsVert/R/dpCapsuleManifestDS.R` | Recognize signed GEE cross-grid specs |
| `dsVert/R/dpCapsuleMaterializer.R` | Recognize GEE cross-input owners and leave ordinary local GEE release blocks zero |
| `dsVert/R/dpCapsuleWorkload.R` | Dispatch GEE through the existing grouped workload path |
| `dsVert/R/dpGLMGridCrossMaterializer.R` | Discover admitted staged GEE artifacts |
| `dsVert/R/dpGLMGridCrossProfile.R` | Admit only authenticated staged analyst-fixed-rho GEE |
| `dsVert/R/dpLMMGridCrossSource.R` | Bind the fixed-correlation token in GEE source handoffs |
| `dsVert/R/dpSynopsisLifecycleDS.R` | Preserve immutable references within signed GEE contracts |
| `dsVert/R/dpSynopsisExecutionDS.R` | Authenticated fixed-rho GEE execution width of at most 16; tested locally, real proof pending |
| `dsVert/R/exactGCTransportDS.R` | Preserve terminal worker failure and private diagnostics through lease checks until explicit abort |
| `dsVert/R/typedBlobTransportDS.R` | Admit capacity-bounded exact publication chunks while retaining authenticated context and segment binding |
| `dsVert/inst/cross-grid-v2/integrator-validation/lmm_native_recovery.R` | Select the GEE native recovery operation |
| `dsVert/inst/cross-grid-v2/integrator-validation/validate_structured_dslite.R` | Fixed-rho GEE fixture, oracle, release/recovery validation and GEE worker failure diagnostics |
| `dsVertClient/R/dp_capsule_manifest.R` | Recognize signed GEE cross-grid specs |
| `dsVertClient/R/dp_gaussian_certificate.R` | Validate GEE provenance and select likelihood coordinates by candidate stride |
| `dsVertClient/R/dp_glm_grid_cross_materializer.R` | Discover admitted staged GEE artifacts |
| `dsVertClient/R/dp_glm_grid_cross_profile.R` | Mirror authenticated fixed-rho admission |
| `dsVertClient/R/dp_glm_grid_cross_release.R` | Reconstruct grouped GEE artifacts during preflight |
| `dsVertClient/R/dp_grouped_grid_cross.R` | Enable authenticated GEE release reader and document fixed rho |
| `dsVertClient/R/dp_grouped_grid_cross_contract.R` | Mirror fixed-correlation declaration and certificate/artifact binding |
| `dsVertClient/R/dp_staged_grouped.R` | Use the GEE family domain in shared staged lifecycle dispatch |
| `dsVertClient/man/dp_grouped_grid_cross.Rd` | Mirror the GEE reader documentation without regenerating adjacent API documentation |
| `dsVertClient/R/exact_gc_transport.R` | Admit the fixed-rho GEE operation, Ring128/q0 purpose binding and GEE output kind |
| `dsVertClient/R/dp_synopsis_vector_runner.R` | Mirror authenticated fixed-rho GEE execution width; tested locally, real proof pending |

Other changed files are GEE-native modules, GEE-only certificates/oracles/tests,
regressions in the existing shared exact-transport and typed-downstream suites,
and lane-specific proof drivers or documentation. Refresh this list if further
shared integration changes are required before the final commit.

## Build outputs deliberately excluded from these source commits

New runtimes are built only inside isolated pod snapshots. The source commits
do not replace these packaged outputs or their checksum file:

- `dsVert/inst/bin/linux-amd64/dsvert-mpc`
- `dsVert/inst/bin/darwin-amd64/dsvert-mpc`
- `dsVert/inst/bin/darwin-arm64/dsvert-mpc`
- `dsVert/inst/bin/windows-amd64/dsvert-mpc.exe`
- `dsVert/inst/bin/SHA256SUMS`

The tagged oracle executables at `logs/structured-oracle.test` and
`dsVert/inst/cross-grid-v2/build/cross-grid-oracle.test`, frozen source manifests,
private state stores and bulk run logs remain proof artifacts rather than
source changes. Record their real hashes and retained evidence locations when
available. The final integration owner must rebuild and pin packaged runtimes
from the merged source before distributing a release; old packaged binaries
do not prove the new source. This record neither changes existing frozen LMM
jobs nor claims that their runtimes include these GEE changes.

The family summary rows reuse the release generator's field names where
applicable and add explicit pending evidence cells. They are not executable
per-job rows and must not be appended to the integrator's global manifest as
completed evidence. The six executable planned rows are in
[RELEASE_MANIFEST_GEE.jsonl](inst/cross-grid-v2/gee-fixed-rho/RELEASE_MANIFEST_GEE.jsonl).
The current six rows and both family summaries bind verified independence-rho0
commitments and r7 manifest `a57e599d16f284612554484ad041f1a43f03a5149eaa040435131e8d13a9294d`,
with `fleet_ready:false` and `promoted:false`. The r6 campaign never launched;
its preflight failure cannot establish r7 release evidence. Historical exchangeable
commitments are retained separately. K2 includes recovery in
its sole publication; K3 and K5 are baselines. Capacity is measured at K3.
Neither these planned rows nor the family summaries assert promotion. No push,
tag or thesis edit is part of this lane.

Pod4 SSH recovered at 08:28 UTC. The earlier eight-job waiter, PID `2478097`,
was confirmed cancelled at 08:28:26 UTC before any n2000 launch, as recorded in
[STATUS_GEE.md](STATUS_GEE.md) and
[CHECKPOINT_GEE.json](inst/cross-grid-v2/gee-fixed-rho/CHECKPOINT_GEE.json).
No n2000 release result, paired pass or capacity result is inferred from a
running process. The r5 continuation launched at 08:53:43 UTC, PID `2610081`,
stdin `/dev/null`, controller SHA256
`9964c40d890a07f8ea575476390c33ff1b5f7ddb03f85a8fb4f0cd9e3591b985`.
Fresh r5 focused R tests passed at 08:55:42 UTC in 113.309429 seconds: 629 server
plus 288 client assertions, zero failures/errors/skips/warnings, with frozen-
source verification passing. It was explicitly cancelled at 09:10:53 UTC
before any n2000 launch; the retained cancellation is in `evidence/r5-cancelled`.
Comparing r4/r5 package inputs allowed historical paired reuse, but r6 changes
package transport/publication code and requires fresh full paired validation.

The r6 controller PID `2728246` started at 09:19:24 UTC with stdin
`/dev/null`; its SHA256 is
`736a8f05d642234c71341bd5b342c10b333c400d16320123e2935d62fd320094`.
Its historical frozen source/build hashes are recorded above and in retained
r6 evidence. It required fresh native
and focused R proof, full exact-transport, session-lease and typed-downstream
tests before both serial n4 preflights, then both complete paired suites before
the six serial n2000 jobs. New independence oracle commitments and a manifest
bound to r6 are complete. Both builds and all 25 top-level native GEE tests
passed with exit zero; native package time was 347.120 seconds and controller
time 377.775880 seconds. The 917 focused R and 1,697 transport regression
assertions also passed without failures, errors, skips or warnings. The
binomial n4 preflight subsequently failed with controller exit 1 after
994.257451 seconds (895.1 seconds R elapsed; peak child RSS 22,097,240 KiB).
The `joint-dp-vector-laplace-v3` worker reported `infrastructure_unavailable`
and exit status -9. All oracle/replay markers were false. The container
`oom_kill` counter increased from 7 before the attempt to 8 afterward. This is
strongly consistent with memory pressure, but available kernel evidence does
not attribute that event to the exact worker PID. The failed gate prevented
Poisson n4, both fresh paired suites and all n2000 jobs from launching.
Neither family is promoted; no n2000 capacity result is inferred.

The r7 execution change is implemented and tested locally; real proof remains
pending. It schedules authenticated GEE in 16/16/11-coordinate chunks while
retaining the full 43-coordinate vector and global sampler plan, sensitivity,
privacy parameters and caps. Since geometry affects the authenticated attempt,
transcript and noise derivation, r7 must use a fresh synthetic proof identity.
It must not migrate or resume r6 private state, or claim recovery of r6. The
r6 snapshot and failed evidence remain immutable. Local validation passed 172
server scheduling/publication assertions, 324 adjacent execution assertions
and 127 client scheduling/adapter assertions, totaling 623. Logs are retained
under `evidence/local` as `gee-fixed16-server-after.log`,
`gee-fixed16-server-adjacent.log` and `sampler-fixed16-client-green-20260920.log`.

The r7 controller PID `2957748` launched at 10:10:10 UTC, stdin `/dev/null`,
with SHA256
`beb9afcce8d4f26f08abd1b7fcbb5a571a4bb3b384624c30906543f65689efc8`.
Current source/build identities are recorded above. Native reuse requires the
trusted r6 manifest/native log/exit, all 614 source inputs and runtime equality.
The tagged oracle is newly built and retains its r7 hash. Synthetic exact
commitments may be reused only after all four JSON hashes and source
dependencies match their retained records; private release state is not reused.
Fresh focused R tests passed 629 server plus 324 client assertions (953 total)
with zero failures/errors/skips/warnings at 10:13:13 UTC in 121.015181 seconds.
The full transport/publication regressions passed 37 cases and 1,740 assertions
with zero failures/errors/skips/warnings at 10:17:06 UTC in 223.732419 seconds.
The 27-file r7 evidence set and its derived summary are hashed above; they do
not establish a completed DP release. The binomial n4 real preflight launched
at 10:17:15 UTC, controller PID `2995126`, stdin `/dev/null`, with the required
900-second inactivity/86,400-second total leases. It remains active without a
completed DP release. Poisson n4, both fresh paired suites and all six n2000
jobs remain pending. Neither the active preflight nor the test passes establish
that memory pressure or publication is resolved; promotion remains pending.

The [capacity observation note](inst/cross-grid-v2/gee-fixed-rho/evidence/local/capacity-observation-20260920.md)
provides public counters and n4 stage timing. Its roughly 57-hour n2000 scaling
projection is a warning, not a measured n2000 result, completion forecast or
lower bound. All caps, including the six-hour acceptance gate, remain unchanged.

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
