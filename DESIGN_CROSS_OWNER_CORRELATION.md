# Server note: cross-owner correlation/PCA, implemented 1.4.2

Implemented after Claude consensus, 2026-10-15. Both R packages are 1.4.2; no push or publication has occurred. Server baseline is `2dba3996764454268b03b82bb2eeb9c220e982bc` (1.4.1), client baseline `04a690341915ac59e2753a331dfb1826f8a01970`.

The implemented consensus design, API choices, evidence, utility analysis, test plan and open questions are in [the client design](../dsVertClient/DESIGN_CROSS_OWNER_CORRELATION.md). This note records the server obligations and intended release boundary.

## Reuse existing computation and release

Use the current signed `bounded-normalized-gaussian-cross-sufficient-statistics-v1` (`spec_version=v2`) with `intercept=TRUE`. The fixed vector already contains all first and second moments for the union of outcome and predictors, including predictor–predictor pairs. One requested variable can serve as the fixed public storage outcome for a correlation-only analysis. No synthetic outcome, new private statistic, sampler, DP allocation, endpoint or wire protocol is needed.

Retain `dsvertDPSynopsisGaussianCross{Bind,Finalize,Evidence}DS` and `dsvertDPGaussianCross{Bind,Prepare,Finalize}DS`, including signed source-layout/transcript/numeric evidence, private complete-case alignment and two designated authorities. All computation owners can contribute to the same pair at K=2/3/5. Client correlation and PCA operate only on the authenticated noised vector. No scores, masks, exact counts, raw cross-products or patient-level values leave the servers.

For m variables with intercept, the Gaussian block has `(m*m+3*m+4)/2` coordinates: n, upper-column-major X'X, X'y, y'y. Its nonnegative bounded contribution gives block natural L1 d/L2 sqrt(d), while the existing catalog also includes the admitted count and three numeric coordinates per variable. Actual calibration remains the complete signed catalog calibration; a minimal add/remove catalog has dimension/sensitivity `1+3*m+d`. Existing Gaussian/finite-sampler delta and exact-Laplace conditional pure-DP statements remain unchanged. Each noise authority contributes a full calibrated independent draw under the existing threat model; no epsilon division by K.

Preserve clipped finite-record means per patient, normalized ties-to-even input quantization, exact protected floor-products, full signed-set complete cases, fixed capacity and bounds, overflow policy and quantization certificate. Correlation requires an intercept; auxiliary univariate marginals cannot substitute for missing complete-case sums. The server public release clamp remains unchanged; PSD projection, additional client moment clamping and PCA eigenstructure are client post-processing.

## Registration and provenance

The outcome/anchor custodian alone owns one `dsvert.dp.gaussian_specs` v2 analysis fragment. Remote variables resolve against the global signed schema: register bare labels when globally unique and owner-qualified labels for collisions. The existing exact local-fragment check rejects noncanonical raw qualified aliases for unique columns; it remains unchanged. Public anchor identities and analyst references may stay qualified. Other custodians approve the global schema/workload and contribute their registered bounded columns; do not duplicate the same analysis-id fragment. All custodians sign existing schema/workload/source/compile receipts and both designated authorities sign computation/release evidence. The analyst selects an existing artifact; it does not select new bounds/budget or rewrite variable roles.

Require the 1.4.1 `dsvert-provenance-epochs-v1` capability and the effective provenance dependency closure E_star, including membership-only participants. Keep frozen authorized publications, private producer seals, random new epochs for explicit publications, event-id retry semantics and authenticated persistent store/UUID checks exactly as described in [PROVENANCE_EPOCHS.md](PROVENANCE_EPOCHS.md). No content-derived identity fallback. New publications compose; stable replay is not a lifetime guarantee.

The August admission revert has no documented author motive. The client history shows it changed tests/docs before production Gaussian Synopsis routing and provenance existed. Later `b0a7c6e` and `8e7a929` supplied/fixed that evidence path. Do not weaken current attestation to implement a reader. A demonstrated client cross-quantization interval/reverification inconsistency must be repaired in the client, with current signed transport tests.

## Implemented server changes

Correct stale descriptive registration/promotion flags and text for NB, LASSO, multinomial and ordinal (`R/crossgrid_nb.R`, `R/crossgrid_lasso.R`, `R/crossgrid_multinomial.R`, `R/crossgrid_ordinal.R`, as applicable). The unused `release_enabled`, `production_release_enabled` and NB `production_release_registered` fields currently report FALSE while promoted authenticated routes exist. Static inspection finds no production reader and no inclusion in signed computational contracts. Replace them with explicit descriptive promotion/production-route metadata. The multinomial/ordinal descriptor `release` callbacks remain fail-closed; the real release route is the existing authenticated Synopsis lifecycle. Keep all actual signature, schema, numerical certificate, mechanism and capability admission checks. No historical exact optimizer is to be exported or registered.

Update README/NEWS and relevant server registration documentation with correlation-only configuration, full-catalog utility, evidence scope and unchanged threat model. Both R packages become 1.4.2 because server metadata/docs also change. No arithmetic or protocol capability version increment is proposed; in particular keep the provenance capability object's `version="1.4.1"` and MPC runtime stamp `1.4.0` unchanged: compatible 1.4.1 servers can serve unchanged artifacts if every required capability is present. Missing capabilities or incompatible descriptors fail closed before private materialization.

Preserve every same-owner artifact/schema/coordinate/replay identity and existing API path. Keep unchanged Go runtime/checksum bytes and runtime identity inputs; a package version bump alone must not silently restamp a binary and defeat retained-domain replay. Any necessary semantic server change discovered later requires renewed design review and an explicit compatibility/identity migration, not a hidden patch.

## Focused verification

Run only named files, each command capped at 900 seconds: Gaussian-cross, capsule workload/materializer correlation tests, selected Synopsis source/execution/attestation/provenance tests, and the four-family registration tests affected by metadata. Check exact same-owner release/certificate bytes, private-source mutation replay, new authorization identity changes and two-authority tamper refusal. No full R or Go suite.

The client design budgets one isolated-process DSLite smoke at at most ten fits/analyses and 15 minutes total, using tiny public synthetic data/capacity and real signing/PSI/noise paths. Ordinary one-process DSLite cannot prove independent server identities. A deadline or partial run is reported as incomplete; historical promotion and mocked unit coverage do not become fresh live-connector evidence.

Environment and baseline commands/results are in `/workspace/dsflower/.tmp/vertcor/ENV.md`; source `/workspace/dsflower/.tmp/vertcor/env.sh`. Toolchains, libraries, binaries and logs are isolated below `.tmp/vertcor`; existing tests also use the default owner-private `/home/dev/.dsvert` state when they do not override it. The environment remains external to both repositories.

Final baseline: client 6,425 passing assertions in 20 files, zero failures/errors/warnings, one optional Cox plaintext-harness skip; server 1,523 passing assertions in eight files with one pre-existing materializer fixture error and no failed assertions/warnings/skips. The fixture simulates two peers under one actual persistent identity and identical authorization/seal context with different frames; the immutable-value seal correctly rejects the second peer. The fixture now isolates identities/pins, expects current v5 metadata and both snapshot/value digests, and explicitly checks that reuse with changed values still fails; production seals are unchanged. All batches completed within 900 seconds. See `.tmp/vertcor/BASELINE.md` and `baseline-materializer-diagnosis.md`. A separate descriptor diagnostic confirms that identical physical column names on different owners require a client canonical-reference validation fix.

## Final scope and evidence

The client implementation includes authenticated offline Cor/PCA, cross-only
quantization/canonical-name fixes, four exported grid families and safe NB/
categorical/LASSO dispatch. Grouped/Cox cross models keep explicit grid APIs.
The complete public inventory documents the remaining MI and survival producer
limitations; no universal cross-owner claim is made. Without a scientific outcome,
freeze the radix-smallest owner-qualified variable as anchor at registration.

See `dsVertClient/inst/validation/v1.4.2/RESULTS.md` for targeted counts, exact
same-owner byte comparisons and the incomplete/live-connector distinction.
No protocol guard is relaxed to make the smoke pass. Native runtime and exact
provenance capability contents remain byte-identical to the 1.4.1 baseline.
