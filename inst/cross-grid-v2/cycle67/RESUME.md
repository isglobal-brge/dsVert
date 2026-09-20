# Cycle67 harvest checkpoint — 2026-09-20

**4/10 promoted**: NB, LASSO, multinomial and ordinal retained.
Fresh harvest at 18:20:17 UTC: 24/28 remote probes succeeded; no new terminal
results. Four probes across shared fleet pods 12, 14 and 15 returned SSH
connection refused again this cycle (pod14 has two registry assignments).
Live state on these pods is unknown; retained controller results are preserved.
All dedicated Cox/GEE probes succeeded. Missing terminal records do not prove
that a release is actively computing. Capacity is descriptive only and never gates promotion.

| Family | Promoted | Evidence still required |
|---|---|---|
| nb / lasso / multinomial / ordinal | Yes | Retained; NB math correction resolved |
| lmm | No | K2 recovery; K2/K3/K5 baselines PASS |
| binomial_glmm | No | Complete four-job math/lifecycle proof; old-pair recovery FAIL retained |
| poisson_glmm | No | Complete four-job math/lifecycle proof |
| cox | No | Dedicated K2 recovery; dedicated K2/K3/K5 baselines PASS; N<=400 scope |
| binomial_gee / poisson_gee | No | Separate lane PENDING; eight dedicated jobs nonterminal |

Shared fleet: 8 terminal / 8 nonterminal, re-scored 6 PASS / 2 FAIL.
Dedicated Cox: 3 terminal PASS / 1 nonterminal. Dedicated GEE: 0 terminal /
8 nonterminal. Dedicated Cox is authoritative; shared Cox duplicates do not
supply its missing recovery proof or invalidate its dedicated passes.

Completed measurements and original source pins are retained in
MEASURED_CAPACITY.json. LMM baselines retain 502b005/4c6c562; Cox retains
c97cd19/28be3cd. Peak RSS unavailable, not inferred. The 256 GB / 8 h reference
is descriptive. No capacity-only failure remains failed in the re-scored records.

Shared-pod recovery state collision remains a reviewer hypothesis, not a
proved Gaussian failure cause. The shared Cox recovery failed before native
readiness (cycle59 diagnosis); neither recovery failure is cleared by capacity
re-scoring. Any future GLMM recovery requires an isolated pod/state path.
Shared joint-DP ownership remains here; GEE must not fork it.

Manifest unchanged: 24 definitions / 16 ready, four each LMM, binomial GLMM,
Poisson GLMM and Cox. Per-row execution pins remain authoritative; future
launch leases are 604800 seconds. No evidence-only repinning of executed code.
Validation passed: re-scoring is idempotent and preserves provenance, lifecycle
facts and measurements; manifest counts and future leases checked. Collection is incomplete for the
three unreachable shared pods; this is not reclassified as a release failure.
No runtime/GEE-owned edit, release restart, frozen hash audit, tag, push or
thesis edit. Relay batching remains deferred until after tagging.

Evidence: integrator-evidence/cycle67-20260920/. Resume harvesting and promote
each family when all four authoritative math/lifecycle jobs pass.
