# Cycle42 checkpoint — 2026-09-20

Execution pair **7ff811c/55f4793**. **4/10 promoted**,
exclusively at **f3795a2/e748f05**: NB, LASSO, multinomial, ordinal. NB resolved.

**LMM/GLMM authenticated relay batching is implemented**, ahead of further Cox
wiring as directed. Source complete-case normalization batches up to 128 rows,
bounded by the existing typed-input ceiling. Ring128->192 conversion batches
256 coordinates; GLMM q0 outcome normalization batches 256 rows and reuses its
public program per shape. At n2000/p3: normalization stages 125->16, conversion
chunks 313->40, GLMM outcome exchanges 63->8. This is schedule reduction, not
a measured 2–3h release claim. Integer expressions, rounding, caps, epsilon/delta,
private validity and fresh per-attempt cryptography are unchanged. Public stage
bounds bind the new schedule; use fresh state, never retrofit frozen workers.
Default GEE batching is unchanged; 21 GEE-owned files verified unchanged.

Verified **28 patched native tests + 12 frozen-baseline tests PASS**,
including complete source-to-loss oracles, retained ML, private carry/sign,
large full/tail batches, bilateral remasking, unilateral persisted replay,
cold/tamper and actual spool workers. Differential routing/outcome opened bytes
match legacy batching. **12 focused R tests/204 assertions PASS**,
including current-runtime Gaussian fallback. No native/R nonpasses. All five
local snapshots retain their original pinned hashes; executable native source
matches the execution commit. Four Go1.25.7 runtimes rebuilt; Linux SHA256:
`24908f68b63c830f716f04ffe18ee845608b4f97cb1f3487868436082b280081`.

**Manifest re-emitted incrementally and finalized: 12 ready LMM/GLMM jobs**,
four/family at the execution pair, with exact CLI and oracle hashes. Nine newly
regenerated commitments match retained exact integers. There are 24 heavy
definitions (Cox/GEE not ready here) and 1080 separate oracle-only definitions.
This is not a new selection campaign or n2000 release/capacity result. The
256GB/21,600-second ceiling is unchanged; fleet capacity reruns are required.

The original cycle16 **LMM n2000 epsilon4 K2 release has finished** on
**bc59147/6ba11a0**: oracle/sticky/cold/tamper PASS, process exit0; capacity FAIL
at **45,958.299 end-to-end seconds**, **24,001,151,241 serialized-RPC bytes**.
Native unique payload was 8,836,356,126 bytes (a different accounting basis).
Recovery was NOT exercised. Its gate exit is1. All2553 frozen source hashes
match. The outer controller still reports stale release_start with no sequence
exit; do not mistake that for an unfinished K2 release. Controller untouched.
Old 502b005/4c6c562 K5 capacity failure remains on its own pair.

Fresh signed n4/K2 LMM recovery smoke: `release-r1/logs/launch.json`, local
PID49191, stdin /dev/null, 24h/15min leases, active at
2026-09-20T15:28:59.005338+00:00. Prepared, bilateral PREPARE and unilateral COMMIT
boundaries observed; complete oracle/recovery/cold/tamper proof still pending.
This precommit snapshot's executable native/R sources match the execution pair;
its frozen manifest records the earlier base plus exact patched hashes.
No n2000 smoke-capacity inference.

Full server->client paired suites launched in the new immutable pod4 snapshot
`/workspace/dsvert/executor-cycle42-lmm-paired-r1`, PID4028047,
stdin /dev/null, exact execution pair, all3025 source/oracle hashes verified.
No terminal paired exit yet. Existing frozen jobs were untouched. The separate
simple client paired suite remains confirmatory and was incomplete when observed.

Shared DP remains owned here: the optional Gaussian certified-support gap retains
the certified-Laplace fallback; GEE must not fork it. No new Gaussian patch,
GEE-owned edit, Cox arithmetic/lifecycle change, tag, push, thesis edit, promotion
or new math blocker. Cox remains N<=400 and publicly gated pending lifecycle.

Pending: harvest current smoke and full paired suites; fleet n2000 serialized-RPC
capacity reruns and remaining heavy promotion gates; then resume Cox artifact/
source/client orchestration. **Batching is no longer pending implementation.**
Evidence: **integrator-evidence/cycle42-20260920/RESUME.md**, `PROOF.json`,
`MANIFEST_VALIDATION.json`, `CAPACITY_LMM_FROZEN_K2.json`, `progress.json`.

Full execution pins: 7ff811c1d93489313992b3b076ebae2908db06c1/55f4793778d4d1613320dfc96e8c7fea576d6a82.

Resume read-only collectors:

```sh
python3 integrator-evidence/cycle42-20260920/collect-current.py
python3 integrator-evidence/cycle42-20260920/observe-paired.py
```

The first verifies hashes and captures current smoke/paired observations; it
never restarts or promotes. Review structured paired results, including warnings
and skips, when complete. Smoke terminal code/metrics are written by its detached
wrapper. Preserve all snapshots. Do not relaunch the completed old K2 release or
modify its still-live outer controller. Its raw result is in frozen-lmm-k2/.

Manifest prepare commands use the execution commits, not a later evidence-only
checkpoint commit. The current native proof is assembled from proof-r1/r2/r3;
r2 adds the outcome differential test, r3 adds the routing differential test.
Production native source is identical across those snapshots and the commit.
The frozen baseline is pre-batching 99886d2/55f4793 (server code equivalent to
6dbbf52); ML and complete source-to-loss oracle/recovery tests pass on both sides.
No n2000 wall-time speedup is yet measured on the patched pair.
