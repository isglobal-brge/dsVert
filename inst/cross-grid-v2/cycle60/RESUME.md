# Cycle60 harvest checkpoint — 2026-09-20

**4/10 promoted**: NB, LASSO, multinomial and ordinal retained.
Fresh harvest at 18:07:54 UTC: all 28 remote probes succeeded; no new terminal
results and no new promotion. Capacity is descriptive only and never gates promotion.

| Family | Promoted | Evidence still required |
|---|---|---|
| nb / lasso / multinomial / ordinal | Yes | Retained promotion; NB resolved |
| lmm | No | K2 recovery; K2/K3/K5 baselines PASS |
| binomial_glmm | No | Complete four-job math/lifecycle proof; old-pair recovery failure retained |
| poisson_glmm | No | Complete four-job math/lifecycle proof |
| cox | No | Dedicated K2 recovery pending; shared K2 recovery FAIL; K2/K3/K5 baselines PASS; N<=400 scope |
| binomial_gee / poisson_gee | No | Separate lane report PENDING; eight dedicated jobs nonterminal |

Shared fleet: 6 terminal / 10 nonterminal; re-scored 4 PASS / 2 FAIL.
Dedicated Cox: 3 terminal PASS / 1 nonterminal. Dedicated GEE: 0 terminal /
8 nonterminal. Controller records and direct observations are captured separately;
remote RESULT.json records are merged by job ID within each lane. Shared and
dedicated Cox executions remain distinct despite identical job IDs.

The shared Cox recovery failure remains a pre-oracle worker-readiness failure
at the unilateral_commit invocation, with native_fired false. It is not a
capacity-only failure or a demonstrated math mismatch. Cycle59 retains its raw
log and diagnosis; the independent dedicated recovery execution is nonterminal.
Old binomial GLMM recovery likewise remains FAIL; no capacity policy clears it.

LMM measurements retain 502b005/4c6c562 provenance: K2 31,727.797 s /
24,009,522,847 serialized-RPC bytes; K3 29,890.088 s / 24,030,965,558 bytes;
K5 22,774.592 s / 24,036,925,468 bytes. All three baselines remain PASS.
Dedicated Cox retains c97cd19/28be3cd: K2 1,805.642 s / 1,924,671,838 bytes;
K3 1,376.989 s / 1,929,295,234 bytes; K5 1,330.511 s / 1,939,365,306 bytes.
Shared Cox K5 remains separately PASS at 1,741.763 s / 1,939,353,181 bytes.
Peak RSS unavailable, not inferred. The 256 GB / 8 h reference is descriptive.

Manifest unchanged: 24 definitions / 16 ready, four each LMM, binomial GLMM,
Poisson GLMM and Cox. Future launch leases are 604800 seconds. Per-row pins
remain authoritative; evidence-only commits do not relabel execution sources.
Shared optional-Gaussian handling remains integration-owned; GEE must not
fork or duplicate it. Relay batching remains deferred until after tagging.

Validation passed: re-scoring is idempotent and preserves provenance, lifecycle
facts and measurements; manifest counts and future leases checked.
No release rerun, runtime/GEE-owned edit, frozen hash audit, tag, push or thesis
edit. Resume harvesting; promote only on complete four-job math/lifecycle proof.

Evidence: integrator-evidence/cycle60-20260920/.
