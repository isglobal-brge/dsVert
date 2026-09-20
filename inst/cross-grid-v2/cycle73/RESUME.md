# Cycle73 harvest checkpoint — 2026-09-20

**4/10 promoted**: NB, LASSO, multinomial and ordinal retained.
Fresh harvest at 18:32:18 UTC: no new terminal results; 24/28 probes succeeded.
Four shared-fleet probes on pods 12/14/15 remain connection-refused. The prior
18:19:51 UTC controller incident reported these pods EXITED; its evidence is
retained with its original timestamp. All dedicated probes succeeded.

| Family | Promoted | Evidence still required |
|---|---|---|
| nb / lasso / multinomial / ordinal | Yes | Retained; NB correction resolved |
| lmm | No | K2 recovery; K2/K3/K5 baselines PASS |
| binomial_glmm | No | K2 baseline infrastructure loss; old-pair recovery FAIL; four-job proof incomplete |
| poisson_glmm | No | K2 baseline infrastructure loss; four-job proof incomplete |
| cox | No | Dedicated K2 recovery; dedicated K2/K3/K5 PASS; N<=400 scope |
| binomial_gee / poisson_gee | No | Separate lane PENDING; eight dedicated jobs nonterminal |

Shared fleet: 10 terminal controller records, re-scored 6 PASS / 4 FAIL;
6 nonterminal. Dedicated Cox: 3 PASS / 1 nonterminal. Dedicated GEE:
0 terminal / 8 nonterminal. Dedicated Cox remains authoritative; shared Cox
duplicates are ignored for promotion. Missing terminal records do not establish
active computation. The GLMM K2 infrastructure losses have no final metrics,
exit code or oracle/lifecycle verdict; they cannot be cleared by re-scoring.

The reviewer-launched isolated binomial GLMM recovery remains RUNNING on
pod-cox-1, as observed by its collector at 18:32:31 UTC. Its distinct source
pair is ad276b5/bf73744; retain this attribution separately from the initial
wave. No terminal recovery result yet. See GLMM_ISOLATED_CHECKPOINT.json.

Capacity is descriptive only. All capacity-only failures are re-scored PASS;
remaining failures lack math/lifecycle proof. MEASURED_CAPACITY.json retains
elapsed time, serialized-RPC bytes and original source pins. Peak RSS remains
unavailable. The 256 GB / 8 h reference never gates promotion.

Manifest unchanged: 24 definitions / 16 ready, four each LMM, binomial GLMM,
Poisson GLMM and Cox. Execution pins remain authoritative; future launch leases
are 604800 seconds. Validation passed: re-scoring is idempotent and preserves
provenance, lifecycle facts and measurements; manifest counts/leases checked.
The updated RECOVERY_DIAGNOSIS.md identifies the Gaussian-support message as
a handled optional admission probe; the terminal failure is alignment-mask
worker startup, whose timeout-versus-child-exit cause remains unproven.
A shared-pod DP-state collision is not established; no sampler repair is justified.
Shared joint-DP remains integration-owned; future GLMM recovery requires an
isolated pod/state path. No runtime/GEE-owned edits, restarts, frozen hash audits,
tags, pushes or thesis edits. Relay batching remains deferred.

Evidence: integrator-evidence/cycle73-20260920/. Continue short authoritative
harvests; promote only when all four family math/lifecycle jobs pass.
