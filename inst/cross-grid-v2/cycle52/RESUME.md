# Cycle52 harvest checkpoint — 2026-09-20

**4/10 promoted**, unchanged: NB, LASSO, multinomial and ordinal.
Fresh read-only harvest at 17:48 UTC: no new completed releases.

| Family | Promoted | Remaining evidence |
|---|---|---|
| nb / lasso / multinomial / ordinal | Yes | Retained promotion at f3795a2/e748f05; NB resolved |
| lmm | No | K2/K3/K5 baseline PASS; K2 recovery pending |
| binomial_glmm | No | Baselines pending; old-pair recovery failed before oracle checks |
| poisson_glmm | No | Four-job math/lifecycle evidence pending |
| cox | No | Wiring DONE; four dedicated jobs nonterminal; N<=400 scope |
| binomial_gee / poisson_gee | No | Separate lane report PENDING; eight dedicated jobs nonterminal |

Shared fleet: 4 terminal / 12 nonterminal registered jobs; captured records
re-score to 3 PASS / 1 FAIL. All completed records retain 502b005/4c6c562
provenance. The three LMM baselines have oracle_equal/cold/tamper and exit0;
none exercises recovery. End-to-end measurements remain:
K2 31,727.797 s / 24,009,522,847 serialized-RPC bytes;
K3 29,890.088 s / 24,030,965,558 bytes;
K5 22,774.592 s / 24,036,925,468 bytes. Peak RSS unavailable.
Old GLMM recovery remains a pre-oracle lifecycle failure, not an established
oracle mismatch or a capacity-only failure.

All four dedicated Cox and eight dedicated GEE probes succeeded and found
neither release.exit nor RESULT.json. Controllers report releases running;
the GEE promotion report remains PENDING. Four additional shared-pool Cox
jobs are tracked separately from the dedicated wave. No duplicate launches.

Capacity NEVER gates promotion. The 256 GB / 8 h reference is descriptive;
math plus cold/tamper/recovery decides promotion. Re-scoring preserves source,
lifecycle and measured values and is idempotent. No missing metric is inferred.

Manifest unchanged: 24 definitions / 16 ready, four each LMM, binomial GLMM,
Poisson GLMM and Cox. Future commands retain 604800-second leases. Per-row
source pins remain authoritative (Cox c97cd19/28be3cd); evidence-only commits
must not relabel old measurements. Shared optional-Gaussian handling remains
integration-owned; GEE must not duplicate or fork it. Batching stays deferred.

Checkpoint evidence: integrator-evidence/cycle52-20260920/. Validation records
preserved provenance, idempotent scoring, manifest counts and seven-day leases.
No runtime/GEE-owned edits, frozen hash audits, oracle recomputation, release
rerun, tag, push or thesis edit. Resume with the same collectors; promote only
when complete family math/lifecycle evidence lands. Do not idle-wait or rerun.
