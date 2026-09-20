# Cycle61 harvest checkpoint — 2026-09-20

**4/10 promoted**: NB, LASSO, multinomial and ordinal retained.
Fresh harvest at 18:09:45 UTC: all 28 remote probes succeeded.
Capacity is descriptive only; promotion requires math and lifecycle evidence.

| Family | Promoted | Evidence still required |
|---|---|---|
| nb / lasso / multinomial / ordinal | Yes | Retained; NB math correction resolved |
| lmm | No | K2 recovery; K2/K3/K5 baselines PASS |
| binomial_glmm | No | Complete four-job math/lifecycle proof; old-pair recovery FAIL retained |
| poisson_glmm | No | Complete four-job math/lifecycle proof |
| cox | No | Dedicated K2 recovery; dedicated K2/K3/K5 baselines PASS; N<=400 scope |
| binomial_gee / poisson_gee | No | Separate lane PENDING; eight dedicated jobs nonterminal |

Shared fleet: 7 terminal / 9 nonterminal, re-scored 5 PASS / 2 FAIL.
Dedicated Cox: 3 terminal PASS / 1 nonterminal. Dedicated GEE: 0 terminal /
8 nonterminal. Dedicated Cox is authoritative; shared Cox duplicate results,
including its recovery FAIL, do not determine Cox promotion.

New shared Cox K3 baseline PASS at c97cd19/28be3cd: oracle_equal/cold/tamper
true, returncode=0; 2,143.125 seconds / 1,929,795,789 serialized-RPC bytes.
This duplicate does not supply the missing dedicated recovery proof.
LMM K2/K3/K5 passes retain 502b005/4c6c562 provenance and measurements;
all completed measurements are retained in MEASURED_CAPACITY.json.
Peak RSS unavailable, not inferred. The 256 GB / 8 h reference is descriptive.

Shared-pod recovery state collision remains a reviewer hypothesis, not a
proved Gaussian failure cause. The shared Cox recovery failed before native
readiness (cycle59 diagnosis); neither failure is cleared by capacity re-scoring.
Any future GLMM recovery must use an isolated pod/state path. Existing releases
were not restarted. Shared joint-DP ownership remains here; GEE must not fork it.

Manifest unchanged: 24 definitions / 16 ready, four each LMM, binomial GLMM,
Poisson GLMM and Cox. Per-row execution pins remain authoritative; future
launch leases are 604800 seconds. No evidence-only repinning of executed code.
Validation passed: re-scoring is idempotent and preserves provenance, lifecycle
facts and measurements; manifest counts and future leases checked.
No runtime or GEE-owned edit, frozen hash audit, release rerun, tag, push or
thesis edit. Relay batching stays deferred until after tagging.

Evidence: integrator-evidence/cycle61-20260920/. Resume harvesting; promote each
family when all four authoritative math/lifecycle jobs pass.
