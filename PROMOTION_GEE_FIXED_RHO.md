# Fixed working-correlation GEE promotion record

**Decision: PENDING. No real release or capacity promotion is asserted.**

Accepted statistical scope: binomial and Poisson GEE with signed,
analyst-specified fixed rho. Independence uses rho=0; exchangeable and AR1 use
rho in {0,1/4,1/2}. The v3 whitening alpha is a fixed coefficient, not an
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
| Current frozen pod snapshot | `/workspace/dsvert/gee-fixed-rho-r4` |
| Current frozen source manifest SHA256 | `1d4b78e617c85b7874d0b56c09f03977e1606a1b0b60e8869d2126e5427934df` |
| Rebuilt Linux amd64 runtime SHA256 | `a59e004567027fc0c09c620cf9ab8dcae0000efb4477f14672997fd800b150c6` |
| Rebuilt tagged integer-oracle SHA256 | `e7415b4a13f534dbeb9e698920ea887f9f965cf09cb69c67a6df21271fd53ec2` |
| Numeric certificate SHA256 | `82df4b2c32f19f0ac248acbd424f079edd5e29546f95e6e3c520c2e2232be3e3` |

The base commits precede the implementation commits above. The r4 manifest
binds the committed pair with no dirty overlay. Its rebuilt binaries come from
the frozen dev-r3 snapshot after all 614 native source inputs, including
`go.mod` and `go.sum`, matched. The dev-r3 source manifest SHA256 is
`cc108c3eb3881957c98534c4d65e73a6c6b09990018cde584db58bb95cdd0305`.
Real release and paired-suite proof remain pending. Detached jobs use
`< /dev/null` in the lane's own `/workspace/dsvert/gee-*` snapshots on pod4.
Do not rewrite a frozen manifest to make an already-running job match new code.

## Exact capacity and statistical scope

The arithmetic certificate admits p<=3 covariates, J<=4, B<=8 and the retained
fixed-correlation set. The requested real release proof is narrower:
**n2000/C500/B4/p3/J2**, epsilon=8, delta=2^-100, q16 output, score clip=1,
exchangeable rho=1/4, K=2/3/5 source owners and two compute/noise authorities.
The count plus complete two-candidate likelihood/bread/meat vector has 43
coordinates. The existing 51-coordinate sampler cap is unchanged; p3/J4 would
require 85 coordinates and is not part of this capacity claim.

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
| Focused native/R/integer-oracle proof on the frozen pod build | PASS native/build dev-r3 and R recheck r4 | Same combined runs |
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
Poisson n4 and the paired suite remain active at this checkpoint, with final
evidence pending. No n2000 release or measured capacity gate is filled.

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

## Shared integration files for the single-owner merge

This is the exact shared-file list from the current diff. Each edit is limited
to GEE admission, dispatch, source bindings, certificate interpretation or the
GEE branch of a reused validation harness; none is a general refactor.

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

Other changed files are GEE-native modules, GEE-only certificates/oracles/tests,
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
They retain the independent n2000 oracle commitments, with source binding and
`fleet_ready:false` pending a new orchestration freeze. K2 includes recovery in
its sole publication; K3 and K5 are baselines. Capacity is measured at K3.
Neither these planned rows nor the family summaries assert promotion. No push,
tag or thesis edit is part of this lane.

Pod4 SSH recovered at 08:28 UTC. The earlier eight-job waiter, PID `2478097`,
was confirmed cancelled at 08:28:26 UTC before any n2000 launch, as recorded in
[STATUS_GEE.md](STATUS_GEE.md) and
[CHECKPOINT_GEE.json](inst/cross-grid-v2/gee-fixed-rho/CHECKPOINT_GEE.json).
No n2000 release result, paired pass or capacity result is inferred from a
running process. The revised serial six-job plan remains local and unlaunched;
no r5 snapshot has been created.
