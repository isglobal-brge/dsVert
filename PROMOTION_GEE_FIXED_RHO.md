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
| Final server implementation commit | PENDING |
| Final client implementation commit | PENDING |
| Frozen pod snapshot/source manifest SHA256 | PENDING |
| Built runtime and integer-oracle SHA256 records | PENDING |
| Numeric certificate SHA256 | `82df4b2c32f19f0ac248acbd424f079edd5e29546f95e6e3c520c2e2232be3e3` |

The base commits do not include the uncommitted GEE changes. Final evidence
must identify both final sources and exact built runtimes. Detached jobs use
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
| Focused native/R/integer-oracle proof on the frozen pod build | PENDING | PENDING |
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

The r1 n4 signed smokes are failed pre-source evidence: ordinary local
materialization reported `The requested numeric variable has no custodian-owned
bounds` because its cross-owner version lists omitted GEE. The r2 correction in
`R/dpCapsuleMaterializer.R` restores zero local GEE release blocks; real r2 proof
remains pending. An optional Gaussian-plan support rejection was caught by the
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
| `dsVert/inst/cross-grid-v2/integrator-validation/validate_structured_dslite.R` | Fixed-rho GEE fixture, oracle, release and recovery validation |
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
completed evidence. No final promotion, push, tag or thesis edit is authorized
by a template.
