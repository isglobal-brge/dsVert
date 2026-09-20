# Cycle77 harvest checkpoint — 2026-09-20

**4/10 promoted**: NB, LASSO, multinomial and ordinal retained.
Authoritative controller records harvested at 2026-09-20T18:41:07.959721+00:00: no new terminal
results. Shared fleet: 10 terminal, re-scored 6 PASS / 4 FAIL; dedicated Cox:
3 PASS; dedicated GEE: no terminal result file. This cycle reads controller
records only; no fresh remote probes or active-computation claim.

| Family | Promoted | Evidence still required |
|---|---|---|
| nb / lasso / multinomial / ordinal | Yes | Retained; NB resolved |
| lmm | No | K2 recovery; K2/K3/K5 baselines PASS |
| binomial_glmm | No | K2 baseline infrastructure loss; isolated K2 recovery and remaining baselines pending |
| poisson_glmm | No | K2 baseline infrastructure loss; remaining four-job evidence pending |
| cox | No | Dedicated K2 recovery; dedicated K2/K3/K5 PASS; N<=400 scope |
| binomial_gee / poisson_gee | No | Separate lane; no terminal results available |

Isolated binomial GLMM recovery collector reports RUNNING at
2026-09-20T18:40:23.054765+00:00 on pod-cox-1, source ad276b5/bf73744.
This is separate from the initial 502b005/4c6c562 wave. Dedicated Cox results
remain authoritative; shared Cox duplicates and superseded shared binomial
recovery failures do not gate their isolated replacements. The GLMM K2 baseline
infrastructure losses still lack oracle/lifecycle proof; capacity re-scoring
cannot supply it. Prior pod12/14/15 incident retained with its own timestamp.

Capacity is descriptive only. Re-scoring preserves source pins, lifecycle facts,
elapsed time and serialized-RPC bytes, and is idempotent. Peak RSS remains
unavailable. The 256 GB / 8 h reference never gates promotion.
Manifest remains 24 definitions / 16 ready, four each LMM, binomial GLMM,
Poisson GLMM and Cox. Exact execution pins retained; future leases 604800 s.

Shared joint-DP remains integration-owned. Gaussian admission rejection is an
expected handled fallback, not the recovery failure; no table/sampler/privacy
change is justified. Recovery resource exclusion remains required. Diagnostic
capture and any conditional startup allowance change remain post-tag work.
No launches, restarts, runtime/GEE-owned edits, frozen hash audits, tags, pushes
or thesis edits. Relay batching remains deferred.

Evidence: integrator-evidence/cycle77-20260920/. Continue short authoritative
harvests; promote when all four family math/lifecycle jobs pass.
