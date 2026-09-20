# Cycle59 harvest checkpoint — 2026-09-20

**4/10 promoted**: NB, LASSO, multinomial and ordinal retained.
Fresh harvest at 18:05 UTC: all 28 remote probes succeeded. No new promotion.
Capacity is descriptive only and never gates promotion.

| Family | Promoted | Evidence still required |
|---|---|---|
| nb / lasso / multinomial / ordinal | Yes | Retained promotion; NB resolved |
| lmm | No | K2 recovery; K2/K3/K5 baselines PASS |
| binomial_glmm | No | Complete four-job math/lifecycle proof; old-pair recovery failure retained |
| poisson_glmm | No | Complete four-job math/lifecycle proof |
| cox | No | Dedicated K2 recovery pending; shared K2 recovery FAIL; K2/K3/K5 baselines PASS; N<=400 scope |
| binomial_gee / poisson_gee | No | Separate lane report PENDING; eight dedicated jobs nonterminal |

New shared-pool Cox K2 recovery FAIL on pod16 at c97cd19/28be3cd:
returncode=1, process wall 1,991.661 s; no completed release metrics.
Prepared and bilateral PREPARE interruption boundaries were observed.
The subsequent unilateral_commit invocation failed during private alignment-mask
start: both authorities report "Exact-gc worker failed before readiness",
with empty worker logs. The native interruption hook had not fired;
terminal assertion is `native_fired is not TRUE`. This is a pre-oracle
lifecycle failure, not a demonstrated math mismatch or capacity-only failure.
The mechanism selector recorded discrete-Laplace explicit fallback; an optional
Gaussian support refusal is also logged but is not established as the cause.
Underlying worker startup cause remains undetermined. Raw log retained in
COX_SHARED_RECOVERY_FAILURE.log. No new math/protocol impossibility established.
Dedicated Cox K2 recovery is a separate execution and remains nonterminal;
do not relaunch it or conflate the two executions despite identical job IDs.

Shared fleet: 6 terminal / 10 nonterminal; re-scored 4 PASS / 2 FAIL.
Dedicated Cox: 3 terminal PASS / 1 nonterminal. Dedicated GEE: 0 terminal /
8 nonterminal. Controller records and direct observations are captured separately;
remote RESULT.json records are merged by job ID within each lane.

LMM measurements retain 502b005/4c6c562 provenance: K2 31,727.797 s /
24,009,522,847 serialized-RPC bytes; K3 29,890.088 s / 24,030,965,558 bytes;
K5 22,774.592 s / 24,036,925,468 bytes. All three baselines remain PASS.
Dedicated Cox retains c97cd19/28be3cd: K2 1,805.642 s / 1,924,671,838 bytes;
K3 1,376.989 s / 1,929,295,234 bytes; K5 1,330.511 s / 1,939,365,306 bytes.
Shared Cox K5 remains separately PASS at 1,741.763 s / 1,939,353,181 bytes.
Peak RSS unavailable, not inferred. The 256 GB / 8 h reference is descriptive.
Old GLMM recovery remains a pre-oracle failure, not a capacity-only failure.

Manifest unchanged: 24 definitions / 16 ready, four each LMM, binomial GLMM,
Poisson GLMM and Cox. Future launch leases are 604800 seconds. Per-row pins
remain authoritative; evidence-only commits do not relabel execution sources.
Shared optional-Gaussian handling remains integration-owned; GEE must not
fork or duplicate it. Relay batching remains deferred until after tagging.

Validation passed: re-scoring is idempotent and preserves provenance, lifecycle
facts and measurements; manifest counts and future leases checked.
No release rerun, runtime/GEE-owned edit, frozen hash audit, tag, push or thesis
edit. Resume harvesting; promote only on complete four-job math/lifecycle proof.

Evidence: integrator-evidence/cycle59-20260920/.
