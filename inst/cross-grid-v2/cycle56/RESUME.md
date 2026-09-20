# Cycle56 harvest checkpoint — 2026-09-20

**4/10 promoted**: NB, LASSO, multinomial and ordinal retained.
Fresh read-only probes at 17:59 UTC found no new completed jobs. The two
dedicated Cox baseline passes are retained; K2 baseline and recovery remain pending.

| Family | Promoted | Remaining evidence |
|---|---|---|
| nb / lasso / multinomial / ordinal | Yes | Retained promotion; NB resolved |
| lmm | No | K2/K3/K5 baseline PASS; K2 recovery pending |
| binomial_glmm | No | Baselines pending; old-pair recovery failed before oracle checks |
| poisson_glmm | No | Four-job math/lifecycle evidence pending |
| cox | No | K3/K5 baseline PASS; K2 baseline/recovery pending; N<=400 scope |
| binomial_gee / poisson_gee | No | Separate lane PENDING; eight dedicated jobs nonterminal |

Cox K3 and K5 both have exit0, oracle_equal, cold and tamper true. Recovery
is not exercised by either baseline. Source pair remains c97cd19/28be3cd.
K3 measured 1,376.989 s / 1,929,295,234 serialized-RPC bytes;
K5 measured 1,330.511 s / 1,939,365,306 bytes. Process wall times were
1,484.260 s and 1,435.489 s respectively. Peak RSS unavailable.
Raw remote RESULT.json bodies and release.exit are retained in
DEDICATED_LIVE_STATUS.json; COX_HARVESTED.jsonl combines those results with
any already-collected controller records without duplicating job IDs.
Controller checkpoints may lag these direct observations.

Shared fleet unchanged: 4 terminal / 12 nonterminal registered jobs,
re-scored to 3 PASS / 1 FAIL with original 502b005/4c6c562 provenance.
LMM baseline K2: 31,727.797 s / 24,009,522,847 serialized-RPC bytes;
K3: 29,890.088 s / 24,030,965,558 bytes;
K5: 22,774.592 s / 24,036,925,468 bytes. Peak RSS unavailable.
Old GLMM recovery remains a pre-oracle lifecycle failure, not a demonstrated
oracle mismatch or capacity-only failure. No completed LMM recovery found.
Four shared-pool Cox jobs remain distinct from the dedicated Cox wave.
GEE RESULTS.jsonl is absent; its eight remote probes found no terminal files
and its lane promotion report remains PENDING. No GEE promotion inferred.

Capacity NEVER gates promotion; the 256 GB / 8 h reference is descriptive.
Re-scoring preserves source, math/lifecycle facts and measurements and is
idempotent. Manifest unchanged: 24 definitions / 16 ready (four each LMM,
binomial GLMM, Poisson GLMM, Cox). Future leases remain 604800 seconds.
Per-row execution pins remain authoritative. Shared optional-Gaussian handling
remains integration-owned; GEE must not duplicate or fork it. Batching deferred.

Evidence: integrator-evidence/cycle56-20260920/. Validation checks passed for
provenance preservation, idempotent scoring, manifest counts and future leases.
No runtime/GEE-owned edits, frozen hash audit, oracle recomputation, release
rerun, tag, push or thesis edit. Resume harvesting; promote each family only
when all four math/lifecycle jobs complete. Do not idle-wait or rerun.
