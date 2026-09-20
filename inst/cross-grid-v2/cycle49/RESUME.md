# Cycle49 harvest checkpoint — 2026-09-20

**4/10 promoted**, unchanged: NB, LASSO, multinomial and ordinal remain Yes
at f3795a2/e748f05. No additional family has four completed math/lifecycle jobs.

| Family | Promoted | Remaining evidence |
|---|---|---|
| nb | Yes | Resolved; corrected loss promotion retained |
| lasso | Yes | Retained promotion |
| multinomial | Yes | Retained promotion |
| ordinal | Yes | Retained promotion |
| lmm | No | K2/K3/K5 baseline PASS; K2 recovery pending |
| binomial_glmm | No | Baselines pending; known old-pair recovery failed before oracle checks |
| poisson_glmm | No | Four-job math/lifecycle evidence pending |
| cox | No | Wiring DONE; dedicated four-job results pending, N<=400 |
| binomial_gee | No | Separate lane promotion PENDING |
| poisson_gee | No | Separate lane promotion PENDING |

Fresh read-only fleet probe: 4 terminal / 12 nonterminal registered jobs.
Re-scored results remain **3 PASS / 1 FAIL**, on their original
502b005/4c6c562 source pair. All three LMM baseline results have oracle_equal,
cold and tamper true with exit0. Recovery is not exercised by these baselines.
K2: 31,727.797 s / 24,009,522,847 serialized-RPC bytes;
K3: 29,890.088 s / 24,030,965,558 bytes;
K5: 22,774.592 s / 24,036,925,468 bytes. Peak RSS remains unavailable.
The old GLMM recovery failure remains unverified on math/lifecycle, not a
capacity-only failure and not evidence of an oracle mismatch.

Dedicated Cox and GEE read-only probes found no release.exit or RESULT.json
on all four Cox and eight GEE pods. Their controllers still report releases
running; the GEE lane's promotion report remains PENDING. Its historical
shared-pool collection state is retained separately. No new completed result
was available to promote. The fleet registry also contains four shared-pool
Cox jobs; these are distinct from the dedicated Cox wave and are not added to
its completion count. No jobs were launched, restarted or stopped.

Capacity NEVER gates promotion. The 256 GB / 8 h reference is descriptive only;
math plus cold/tamper/recovery decides promotion. Missing capacity metrics are
not inferred. Re-scoring is idempotent and preserves source and lifecycle facts.

Manifest retained unchanged: 24 definitions, 16 ready, four each for LMM,
binomial GLMM, Poisson GLMM and Cox. All future commands use a 604800-second
lease. Per-row source pins and oracle commitments remain authoritative; existing
measurements are not attributed to newer commits. Cox retains c97cd19/28be3cd.
Shared optional-Gaussian handling remains integration-owned; GEE must not fork
that fix. Batching stays deferred. No GEE-owned or runtime edits, hash audit,
oracle recomputation, heavy rerun, tag, push or thesis edit.

Validation: captured-record scoring preserves source/oracle/lifecycle/metrics,
is idempotent, and retains the non-capacity failure. Manifest count, ready count,
seven-day leases and non-gating capacity flags pass. No production code changed.

Evidence: integrator-evidence/cycle49-20260920/. Resume by harvesting the same
collectors; promote when the missing jobs complete. Do not idle-wait or rerun.
