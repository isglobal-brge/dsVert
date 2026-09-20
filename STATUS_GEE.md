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

The current proof snapshot is `/workspace/dsvert/gee-fixed-rho-r5`, from server
source commit `a3964d39c26909d8f805f64cbfe2ad3a81b138b5` and the unchanged client
implementation commit above. Its frozen manifest SHA256 is
`f6f7e9543975ffd0de441fce2c4259088f7446040fdfc1f9216cea7795cae6d0`.
It reuses the r3 rebuilt runtime and tagged oracle after matching all 614 native
source inputs, including `go.mod` and `go.sum`, and verifying the copied runtime
and oracle hashes. Exact build hashes are recorded
in [PROMOTION_GEE_FIXED_RHO.md](PROMOTION_GEE_FIXED_RHO.md). Build and proof use
this lane's own `/workspace/dsvert/gee-*` snapshots on pod4. The
integrator worktrees and frozen LMM jobs are not this lane's execution targets.

## Accepted scope and unchanged contract

- Families: `binomial_gee`, `poisson_gee`; composition `staged_fixed_rho_v1`;
  signed correlation contract `signed-analyst-fixed-rho-v1`.
- Independence requires rho=0. Exchangeable and AR1 admit rho in {0,1/4,1/2}.
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
  owners with two compute/noise authorities. The default measured correlation
  cell is exchangeable rho=1/4. It has 42 GEE coordinates plus the count, within
  the unchanged 51-coordinate sampler limit. A successful default-cell release
  does not measure every retained rho/correlation or the larger J4 domain.
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
| Frozen pod build and focused native/R/integer-oracle tests | PASS native/build dev-r3 and R recheck r5 | Same combined runs |
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
its GEE producer completed. Poisson n4 and the paired suite remain active at
this checkpoint; their final results are pending. Neither active nor failed
jobs fill a release gate.

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

## r4 sampler failure and pending serial campaign

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
failure.** Poisson n4 and the paired suite remain active with final evidence
pending; no real release or measured capacity result is inferred.

The local GEE diagnostic patch now includes the captured operation/error
message and available worker exit status in main/recovery failure reports.
The campaign schedules one release at a time, with two authorities per release,
as a resource mitigation. All privacy, numeric, transport and acceptance caps
remain unchanged. No 8 MiB transport-chunk change was made: the retained client
DSI expression cap is 786,431 bytes.

Both independent n2000 integer commitments are complete and source-verified:
binomial `6226c79ddfccb4068a41e91056f13a5bf1c24753e9a0581c716d0d108f6e6feb`,
Poisson `b245f22eaced4faa21b2c2e05ac13f4d3ff5f05616f5b72a4744a91879ec2821`.
These are plaintext synthetic oracle commitments, not authenticated DP releases.
The local six-row [release manifest](inst/cross-grid-v2/gee-fixed-rho/RELEASE_MANIFEST_GEE.jsonl)
plans one publication per family/topology: K2 includes recovery, K3 supplies the
ordinary capacity measurement, and K5 supplies the remaining topology proof.
The r5 source freeze is complete; proof execution remains gated and
`promoted:false`.

[CHECKPOINT_GEE.json](inst/cross-grid-v2/gee-fixed-rho/CHECKPOINT_GEE.json)
records exact own-job PIDs, snapshot paths, evidence bindings and continuation
steps. The r5 continuation launched at **08:53:43 UTC**, PID `2610081`, with
stdin `/dev/null`. Its controller SHA256 is
`9964c40d890a07f8ea575476390c33ff1b5f7ddb03f85a8fb4f0cd9e3591b985`.
Fresh r5 focused R tests passed at **08:55:42 UTC** in 113.309429 seconds:
629 server plus 288 client assertions, zero failures/errors/skips/warnings,
with frozen-source verification passing. The continuation is now waiting for
the r4 Poisson controller to exit. Before fresh smokes it also requires the
full r4 paired suite to pass,
and old sampler PIDs `2496615`/`2496655` to finish. Paired-source comparison
found only the standalone GEE failure-diagnostic harness changed across all
R/Go/certificate/runtime inputs; package code and tests are identical.

It then runs the two fresh n4 families serially. Only successful source-bound
smokes and all remaining gates permit the six serial n2000 jobs. **No n2000
job has launched and neither family is promoted.** Any failed required gate
stops subsequent jobs.

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
