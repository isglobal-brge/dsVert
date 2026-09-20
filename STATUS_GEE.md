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

These are the bases, not commits containing the current GEE changes. Final
implementation commits and the frozen build/source manifests remain to be
recorded in [PROMOTION_GEE_FIXED_RHO.md](PROMOTION_GEE_FIXED_RHO.md). Build and
proof use this lane's own `/workspace/dsvert/gee-*` snapshots on pod4. The
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
| Frozen pod build and focused native/R/integer-oracle tests | PENDING | PENDING |
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
The real r2 smoke/release proofs remain pending; r1 is failed evidence and
cannot supply a promotion or capacity cell.

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
