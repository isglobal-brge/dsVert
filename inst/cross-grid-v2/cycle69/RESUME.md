# Cycle69 harvest checkpoint — 2026-09-20

**4/10 promoted**: NB, LASSO, multinomial and ordinal retained.
Harvest at 18:23:53 UTC found two new controller-recorded infrastructure
FAILs: binomial GLMM K2 baseline (pod12) and Poisson GLMM K2 baseline
(pod15). The fleet's 18:19:51 UTC RunPod incident records pods 12/14/15
EXITED, runtime null. Neither GLMM baseline has final metrics, an exit code,
or an oracle/lifecycle verdict. These are not math failures or capacity-only
failures; re-scoring cannot supply the missing proof. Original 502b005/4c6c562
pins and checkpoint-log paths are preserved. No rerun was launched.

| Family | Promoted | Evidence still required |
|---|---|---|
| nb / lasso / multinomial / ordinal | Yes | Retained; NB correction resolved |
| lmm | No | K2 recovery; K2/K3/K5 baselines PASS |
| binomial_glmm | No | K2 baseline infrastructure loss; old-pair recovery FAIL; four-job proof incomplete |
| poisson_glmm | No | K2 baseline infrastructure loss; four-job proof incomplete |
| cox | No | Dedicated K2 recovery; dedicated K2/K3/K5 PASS; N<=400 scope |
| binomial_gee / poisson_gee | No | Separate lane PENDING; eight dedicated jobs nonterminal |

Shared fleet: 10 terminal controller records (including the two infrastructure
loss records), re-scored 6 PASS / 4 FAIL; 6 nonterminal. Dedicated Cox:
3 PASS / 1 nonterminal. Dedicated GEE: 0 terminal / 8 nonterminal.
Dedicated Cox remains authoritative; shared Cox duplicates are ignored for
promotion. Pod14's retained completed baseline results remain valid.

24/28 probes succeeded; four shared-fleet probes still returned connection
refused on pods 12/14/15. All dedicated probes succeeded. Nonterminal records
alone do not prove active computation. Infrastructure incident captured in
INFRASTRUCTURE_INCIDENT.json; no new Gaussian root-cause claim is made.
Shared-pod recovery state collision remains a hypothesis; shared joint-DP
ownership remains here, and future GLMM recovery requires isolated pod/state.

Capacity is descriptive only. All capacity-only failures are re-scored PASS;
remaining failures lack math/lifecycle proof. Completed elapsed/serialized-RPC
measurements and source pins are retained in MEASURED_CAPACITY.json. Peak RSS
is unavailable, not inferred. The 256 GB / 8 h reference is not a promotion gate.

Manifest unchanged: 24 definitions / 16 ready, four each LMM, binomial GLMM,
Poisson GLMM and Cox; exact execution pins retained. Future launch leases are
604800 seconds. Validation passed: idempotent re-scoring preserves provenance,
lifecycle facts and measurements; manifest counts and future leases checked.
No runtime or GEE-owned edits, frozen restart, hash audit, tag, push or thesis
edit. Relay batching remains deferred. Continue harvesting authoritative
results; do not promote incomplete families or rerun the heavy wave.

Evidence: integrator-evidence/cycle69-20260920/.
