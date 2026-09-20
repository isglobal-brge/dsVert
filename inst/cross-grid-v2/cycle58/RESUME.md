# Cycle58 harvest checkpoint — 2026-09-20

**4/10 promoted**: NB, LASSO, multinomial and ordinal retained.
Fresh harvest at 18:03 UTC: all 28 remote probes succeeded. Two new Cox
baseline results passed; no family has newly completed all four jobs.
Capacity is descriptive only and never gates promotion.

| Family | Promoted | Evidence still required |
|---|---|---|
| nb / lasso / multinomial / ordinal | Yes | Retained promotion; NB resolved |
| lmm | No | K2 recovery; K2/K3/K5 baselines PASS |
| binomial_glmm | No | Complete four-job math/lifecycle proof; old-pair recovery failure retained |
| poisson_glmm | No | Complete four-job math/lifecycle proof |
| cox | No | K2 recovery only; dedicated K2/K3/K5 baselines PASS; N<=400 scope |
| binomial_gee / poisson_gee | No | Separate lane report PENDING; eight dedicated jobs nonterminal |

Dedicated Cox K2 newly passed with oracle_equal/cold/tamper true and exit0:
1,805.642 s / 1,924,671,838 serialized-RPC bytes. Dedicated K3 and K5 retain
PASS at 1,376.989 s / 1,929,295,234 bytes and 1,330.511 s / 1,939,365,306 bytes.
The shared-pool Cox K5 also newly passed: 1,741.763 s / 1,939,353,181 bytes.
These are distinct executions, retained separately despite identical job IDs.
All Cox records retain c97cd19/28be3cd provenance. Baselines do not establish
recovery. Peak RSS is unavailable, not inferred.

Shared fleet: 5 terminal / 11 nonterminal; re-scored 4 PASS / 1 FAIL.
Dedicated Cox: 3 terminal PASS / 1 nonterminal. Dedicated GEE: 0 terminal /
8 nonterminal; RESULTS.jsonl absent. Controller records and direct observations
are captured separately; remote RESULT.json records are merged by job ID within
each lane. Shared-pool Cox jobs remain distinct from the dedicated wave.

LMM measurements retain 502b005/4c6c562 provenance: K2 31,727.797 s /
24,009,522,847 serialized-RPC bytes; K3 29,890.088 s / 24,030,965,558 bytes;
K5 22,774.592 s / 24,036,925,468 bytes. All three baselines remain PASS under
the no-time-invalidation policy. The 256 GB / 8 h reference is descriptive.
Old GLMM recovery failed before oracle checks; it is not a capacity-only
failure or an established oracle mismatch.

Manifest remains current for scheduling: 24 definitions / 16 ready, four each
LMM, binomial GLMM, Poisson GLMM and Cox. Per-row source pins remain authoritative;
future launch leases are 604800 seconds. Evidence-only commits do not repin
execution sources or relabel measurements. Shared optional-Gaussian handling
remains integration-owned; GEE must not duplicate or fork it. Batching deferred.

Validation passed: re-scoring is idempotent and preserves source, math/lifecycle
facts and measurements; manifest counts and seven-day future leases checked.
No release rerun, runtime/GEE-owned edit, frozen hash audit, tag, push or thesis
edit. Resume harvesting; promote when each family's four math/lifecycle jobs
are complete. Do not idle-wait or duplicate runs.

Evidence: integrator-evidence/cycle58-20260920/ (raw records, probes,
re-scored results, measured capacity, validation and progress).
