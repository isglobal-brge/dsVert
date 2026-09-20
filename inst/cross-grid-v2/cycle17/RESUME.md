# Cycle17 checkpoint — isolated GLMM queue launched; no n2000 promotion proof

## Reviewer milestone vs actual evidence

The incoming reviewer note claimed the first LMM n2000 bitwise-equal release.
Read-only inspection of cycle16 r1/r2 logs found that marker ONLY for n4.
At 06:02:26 UTC, r2 n2000 K2 still had 192 COMMIT stages per authority and
`lmm.source.ring192` RUNNING, first recorded around04:03 UTC. This is
unauthenticated progress metadata, not oracle proof. No n2000 metrics/exit or
K3/K5/recovery/paired result exists. The reviewer was asked for the alternative
snapshot/log; none supplied at checkpoint. **LMM Promoted=No. 0/10 promoted.**

The immutable cycle16 r2 source remains bc59147/6ba11a0, controller1182464,
24h total/15min idle, with full source rechecks. Its existing sequence already
runs n4 -> n2000 K2 -> K3 -> K5 -> recovery -> full paired under one lock.
Do not duplicate, alter, stop or restart it. Its n4 proof cost133,037,470
serialized aggregate-RPC bytes/728.767s; this is NOT n2000 capacity.

## Fresh GLMM binomial then Poisson

Frozen `/workspace/dsvert/executor-cycle17-glmm-release-r1`, controller1984876,
stdin/dev/null, source **cd54dd5a38d4f229d0b6595fa64ecb050ac4ebd8** /
**6ba11a0f1ebc4a4400ce444fc32d81ed54aadb03**.2556 files verified; manifest
692d7960a40825911c16f79aa8b1142f7a0632666e2447a4796523f2a899e23f.
Native runtimes unchanged from b59d34c; oracle rebuilt with retained test tags.

The queue runs the existing cycle16 driver with explicit family selection:
- binomial n4/K2, n2000 K2/K3/K5/recovery, server+client full paired;
- then Poisson with the same sequence, only if binomial's sequence succeeds.

Each sequence uses `/workspace/dsvert/cycle14-heavy-release.lock`; binomial is
currently waiting behind LMM. Every release uses fresh isolated DSLite peers,
state roots and24h/15min settings, including cold boots. Gates remain256GB/6h
with strict family/shape/oracle/cold/tamper/recovery checks.18 synthetic driver
cases passed; these are not actual releases or capacity measurements. Family
logs live in `logs/binomial_glmm` and `logs/poisson_glmm`. Paired warnings/skips
still require manual review; the driver never promotes. A failed sequence
stops the queue. Existing old Poisson snapshot/queue remains unchanged.

Local watcher69790, stdin/dev/null, exact start/hash in watch-launch.json,
retains sparse transitions under captures/. Existing collectors remain intact.

```sh
python3 integrator-evidence/cycle16-20260920/harvest.py --verify-source
python3 integrator-evidence/cycle17-20260920/harvest.py --verify-source
./pod4 'cat /workspace/dsvert/executor-cycle17-glmm-release-r1/logs/binomial_glmm/progress.json'
```

## Original binomial and old paired harvest

Original cycle11 binomial K2 FAILED exit1 on the six-hour total operation lease:
`Exact MPC total runtime lease expired before both peers committed output`.
Its complete frozen logs and source hashes are in cycle12/driver-harvest/captures/
2026-09-20T055906.172168_0000. All2500 LMM/2526 binomial source files match.
No old-snapshot measurement is relabelled as current runtime evidence.

Cycle12 paired partial harvest at05:58:41 UTC reverified2526 files. Server:
1170 tests/21264 assertions, zero failures/errors/warnings/skips. Client still
pending. See cycle12/paired/harvest-partial-20260920T055826Z. This is not a
passing full pair and belongs to ba436a1/496c053.

## Cox code advancement

Production source commit **c005226** adds internal Cox workload projection,
transport layout, signed source-context validation, pinned-pair alignment checks
and actual authenticated-store input reading. It preserves event/time descriptors,
no intercept, whole-cohort caps, all source owners and two compute authorities.
Time has validity only, no observed-time value lane. Stored private row MACs,
source/recipient/chunk identities and all-owner completeness are verified.

Focused Cox suite:14 tests/837 assertions PASS, no failures/errors/warnings/skips
(cox-tests-r4.csv/log). Tests exercise K2/K3/K5 context and real SQLite store MAC,
source-count, identity, workload and alignment tampering. Earlier failing test
logs retained: r1 assumed the wrong error class; r3 fixture accidentally renamed
peer-binding metadata. Those test defects were corrected. No native binaries
changed. These are internal components, not signed release proofs.

Remaining Cox: exact binary64 rational->f50 producer integration and authenticated
owner-local time sidecar; private complete-case composition of additive validity
words and row presence; connect f100 predictors/live-event to native preparation;
durable lifecycle/DP/client reader; signed n4 then n2000. The new loader deliberately
returns additive validity words, never relabelled as XOR stage validity/live bits.
Public discovery/runtime remains closed. See cycle14 Cox integration map for
remaining downstream boundaries; its workload/loader items are now partly done.

GEE scope: see GEE_ALPHA_SCOPE.md. Estimator, projection/degenerate cases,
coefficient privacy and global sensitivity contract remain unanswered. Fixed-rho
v3 component proofs are not estimated-alpha admission. No math blocker asserted.

No tags, pushes, thesis edits, simple-family releases, old-tree clobbering or
ULTRA escalation. Harvest actual proof and measure complete release capacity
before promotion; do not infer completion from reviewer prose or progress counters.

Final source-verifying harvests: cycle16 captures/20260920T060447973774Z and
cycle17 captures/20260920T060455466356Z; both controller start identities match,
no source mismatches. Cycle16 remains release_start n2000/K2; GLMM binomial
remains waiting_for_shared_release_lock.

Read-only06:02:58–06:03:43 sample:12,164,656 aggregate ACK payload bytes
advanced in45.0036s (~270304bytes/s); cgroup nr_throttled delta0. See
transport-reviewed.json. This confirms progress only, not final capacity,
physical wire or serialized aggregate-RPC measurements, or the cause of slowness.
