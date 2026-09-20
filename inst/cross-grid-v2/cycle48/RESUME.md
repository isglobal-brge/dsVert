# Cycle48 harvest checkpoint — 2026-09-20

**4/10 promoted**: NB, LASSO, multinomial, ordinal remain Yes at
f3795a2/e748f05. No heavy family yet has all four completed math/lifecycle jobs.
This checkpoint supersedes the stale cycle46 Cox and capacity status below.

Capacity NEVER gates promotion. The 256 GB / 8 h reference remains descriptive;
report measured elapsed seconds, serialized-RPC bytes and peak RSS (unavailable
in the four collected records). Future manifest leases are 604800 seconds;
existing frozen leases and execution sources are untouched.

| Family | Promoted | Current evidence / remaining gate |
|---|---|---|
| nb | Yes | Corrected loss and retained simple evidence; resolved |
| lasso | Yes | Retained simple promotion |
| multinomial | Yes | Retained simple promotion |
| ordinal | Yes | Retained simple promotion |
| lmm | No | K2/K3/K5 baseline PASS; K2 recovery pending |
| binomial_glmm | No | Old-pair recovery FAIL; current wave evidence pending |
| poisson_glmm | No | Four-job math/lifecycle evidence pending |
| cox | No | Fleet-ready; four dedicated releases running, zero results |
| binomial_gee | No | Separate dedicated GEE wave running |
| poisson_gee | No | Separate dedicated GEE wave running |

Fleet harvest: **4 terminal / 12 running**. Re-scored terminal records:
**3 PASS / 1 FAIL**, retaining 502b005/4c6c562 provenance. LMM baseline
K2: **31,727.797 s / 24,009,522,847 RPC bytes**; K3:
**29,890.088 s / 24,030,965,558 bytes**; K5:
**22,774.592 s / 24,036,925,468 bytes**. All three have oracle_equal,
cold and tamper true with exit0; none exercises recovery. K2/K3 capacity-only
FAILs are now PASS without re-execution. The old binomial GLMM recovery remains
FAIL (oracle/cold/tamper/recovery false); no capacity policy can clear it.

Cox wiring is DONE, not a remaining task. Four rows retain the execution pair
c97cd19/28be3cd and N<=400 scope; evidence-only archive 02d7619. Dedicated
controller reports four releases running. No Cox wiring was changed.
GEE dedicated controller reports eight releases running. Its older shared-pool
collector says stopped_requires_review with AssertionError and no releases;
this is retained as separate evidence, not a failure of the dedicated wave.
No completed GEE promotion report was found. GEE-owned files were not edited.

Manifest: 24 definitions, 16 ready (four each LMM, binomial GLMM, Poisson GLMM,
Cox); existing source pins/oracle commitments preserved. Seven-day future lease
and descriptive capacity policy applied. No oracle recomputation or frozen hash
audit. Do not rerun or duplicate active waves. Shared optional-Gaussian handling
remains integration-owned and unchanged; GEE must not fork a sampler fix.
Relay batching stays deferred. No runtime/native/client change, new release,
tag, push or thesis edit.

Validation: seven focused manifest/scoring tests PASS, including over-reference
and missing capacity measurements, preserved source provenance, idempotent
re-scoring, and rejection of missing math/lifecycle proof. Fleet original inputs
remain archived by its finalizer. Resume by harvesting the same result sources
and promoting only complete family/source evidence; do not idle-wait or re-audit.

Evidence: integrator-evidence/cycle48-20260920/{FLEET_RESCORED.jsonl,
MEASURED_CAPACITY.json, FLEET_LIVE_STATUS.json, COX_CHECKPOINT.json,
GEE_CHECKPOINT.json, GEE_COLLECTION_STATE.json, progress.json, tests.log}.
