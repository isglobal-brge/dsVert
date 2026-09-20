# Cycle43 checkpoint — 2026-09-20

Execution/manifest pair **f96717e/0518007**.
**4/10 promoted**, still at **f3795a2/e748f05**. NB remains resolved.
The latest David directive J supersedes cycle42's batching/rerun/6-hour prose.

**Admitted release envelope: 256,000,000,000 serialized-RPC bytes / 28,800 seconds (8 h).**
Shared `inst/cross-grid-v2/integrator-validation/release-capacity.json` drives the
manifest and sequential release driver for future snapshots. Existing frozen jobs
retain their original code/config. The retained fleet finalizer now re-scores
measured records using this policy and archives original inputs by SHA256.
No heavy release was restarted or re-executed. Repeated scoring preserves the
original verdict and never changes source, oracle, cold, tamper or recovery facts.

The two collected fleet records now score **1 PASS / 1 FAIL** on their ORIGINAL
**502b005/4c6c562** pair. **LMM epsilon8 K5 PASS**: oracle/cold/tamper, exit0,
**22,774.592 end-to-end seconds / 24,036,925,468 serialized-RPC bytes**.
Its inner elapsed22607.515 is not the end-to-end capacity measurement. Native
unique payload8,838,064,187 is recorded separately. Recovery was not requested.
Old GLMM K2 recovery still FAILS before oracle validation; changing capacity
cannot clear that failure. Ten fleet jobs remained running at the latest harvest.
No heavy family has complete topology/recovery evidence, so no new promotion.
The older cycle16 epsilon4 LMM K2 at45,958.299s still fails the8-hour ceiling.

**Batching deferred from this line.** Preserved `7ff811c` on
`post-tag/lmm-glmm-relay-batching`; reverted it with `24da71f`.
All native source and packaged runtimes are byte-identical to pre-batching
`99886d2`. Frozen batch-proof/release/paired snapshots were untouched. Their
results belong to that separate runtime and cannot be attributed to this pair.
The separate signed n4 LMM smoke has now completed exit0: all oracle, recovery,
cold and tamper markers PASS; all3024 frozen hashes match. Its full paired suite
remains incomplete (3025 hashes match). This is no n2000 capacity claim.
The eventual tag/source decision remains separate; old fleet metrics do not
establish measured capacity of new source commits. No tags or pushes.

**Cox client integration advanced:** exact source lane projection now agrees
with server K2/K3/K5 layouts; time values/routes remain owner-local, with only
private time-presence validity in transport. The owner-first bind helper checks
the pinned owner's real signature and source/semantic/artifact/profile/certificate
bindings before forwarding its public routing receipt; it then checks bilateral
bound-stage equality. No private routes enter the client. N<=400 retained.
Public discovery/admission stays closed: runner/certificate/workload dispatch,
full signed DP lifecycle proof and the FIRST Cox fleet run remain pending.

Focused R proof: **37 tests / 3248 assertions PASS**,
zero nonpasses. New client transport tests use a fan-out test double, real Ed25519
signatures, and the actual server source projection/key. Existing Cox server and
public cold evidence tests are included. This is not full paired or real Cox DP
release proof. Capacity boundary/nonfinite/missing-data/lifecycle tests pass.
Shared optional-Gaussian fallback passes against the restored native runtime;
shared DP remains owned here, and the GEE lane must not fork a fix.
GEE-owned native/certificate/oracle files and crossgrid_grouped.R are unchanged.

Manifest refreshed: **12 ready LMM/GLMM definitions**, four per family, plus
Cox/GEE placeholders and1080 separate oracle-only definitions. Nine commitments
were regenerated at29a9921/55f4793 and match retained exact integers. Their
origin records remain immutable. Final-pair projections verify identical oracle
dependencies (all server R/native/helper/oracle inputs, and the sole client
integer helper); no computation at a different pair is silently relabeled.
`RELEASE_MANIFEST_STATUS.json` explicitly says **harvest/re-score the existing
wave; do not rerun it**. Ready definitions are not an instruction to duplicate it.

Measured capacity below is separate from promotion. Envelope **256 GB / 8 h**
applies uniformly; simple rows report maxima across their nine retained cells.
No missing measurements are treated as zero or extrapolated from kernel costs.

| Family | Promoted | Measured serialized RPC bytes | Measured release seconds | Evidence scope |
|---|---|---:|---:|---|
| nb | Yes | 3563865032 | 4513.6 | Nine retained simple cells |
| lasso | Yes | 2847066650 | 3862.188 | Nine retained simple cells |
| multinomial | Yes | 6879476337 | 7021.332 | Nine retained simple cells |
| ordinal | Yes | 4196242255 | 4946.68 | Nine retained simple cells |
| lmm | No | 24036925468 | 22774.592 | Old-pair epsilon8 K5 baseline only |
| binomial_glmm | No | — | — | No completed authenticated measurement here |
| poisson_glmm | No | — | — | No completed authenticated measurement here |
| binomial_gee | No | — | — | Pending; GEE owned separately |
| poisson_gee | No | — | — | Pending; GEE owned separately |
| cox | No | — | — | No completed authenticated measurement here |

Simple confirmatory paired suite now COMPLETE on f3795a2/e748f05: client
1150 tests /33908 passing assertions, zero failures/errors/warnings,5 test-level
skips plus the separate module-level DSLite exclusion. All2504 frozen source
hashes matched the existing collector. The server retained1164 tests/21062
assertions with zero nonpasses. Skips are reviewed and retained in
SIMPLE_PAIRED_CONFIRMATION.json; no family-specific defect was reported.
The promotion manifest records this confirmation without changing source pins.

Pending: finish Cox workload/client runner/certificate integration and signed
small lifecycle, then emit its first fleet rows; harvest/re-score remaining heavy
jobs and promote only complete proven family/source sets; harvest full paired
evidence. No new math blocker, simple release,
GEE edit, thesis edit, tag, push, or frozen-worker mutation.

Evidence: **integrator-evidence/cycle43-20260920/RESUME.md**, `PROOF.json`,
`FLEET_RESCORED.jsonl`, `MEASURED_CAPACITY.json`, `MANIFEST_VALIDATION.json`,
`ORACLE_DEPENDENCY_EQUIVALENCE.json`, `REVERT_VERIFICATION.json`, `progress.json`.

Resume collectors (read-only for running workloads):
- `python3 ../dsvert-fleet-heavy/poll.py`
- `python3 ../dsvert-fleet-heavy/finalize_results.py` re-scores collected records;
  originals are retained in fleet-heavy/artifacts/capacity-rescore-inputs/.
- `python3 integrator-evidence/cycle42-20260920/collect-current.py` harvests the
  SEPARATE deferred-batching smoke/paired snapshots, never promotes/restarts.
- `python3 integrator-evidence/cycle42-20260920/observe-paired.py` observes the
  confirmatory simple client suite.
Cox map: cycle41 COX_WIRING_NEXT.md remains applicable except the source-block
projection and authenticated owner-first bind helper now exist in client
`dp_cox_grid_cross_release.R`; public dispatch has deliberately not been enabled.
Do not restore batching from the preserved branch before the release tag.
