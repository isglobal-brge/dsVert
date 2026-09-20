# Cycle16 checkpoint: lease policy configured; passing n2000 gate still pending

Read `LEASE_DIAGNOSIS.md` and `latest.json` first. **0/10 promoted.**
The priority remains one actual LMM n2000 K2 release with bitwise oracle equality,
then K3/K5/recovery/paired and promotion. GEE alpha scope and Cox were not advanced.

## Running proof

Frozen `/workspace/dsvert/executor-cycle16-lmm-release-r2`:
- Server **bc59147a2e94d0dd835bf6cb74ebaea81afa29fe**.
- Client **6ba11a0f1ebc4a4400ce444fc32d81ed54aadb03**.
- Native production runtimes unchanged from **b59d34c**; four checksums verified.
- 2553 frozen files checked; manifest SHA256
  `0956a5547b41bf0ef2ce31eea893f245f3de3c3be402a31375a43a87ccb922ab`.
- Detached controller **1182464**, stdin `/dev/null`; exact start identity and
  command in `launch.json`. Source tree and all logs must remain preserved.
- Holds `/workspace/dsvert/cycle14-heavy-release.lock`, shared with Poisson.
  Legacy binomial/paired jobs remain unchanged on separate transports. This is
  **per-transport isolation**, not a claim of exclusive pod CPU.
- n4/K2 smoke started **01:39:28 UTC**. Effective 900-second inactivity and
  86400-second total leases were observed on both initial and pinned peers.
  At checkpoint it has passed bootstrap/PSI/signing/admission and reached the
  signed release path; no complete smoke or n2000 result yet.
- Sequence: n4/K2 -> n2000/K2 -> K3 -> K5 -> n2000/K2 recovery -> server/client
  full paired suites. Each release uses fresh peer processes/state directories.
  Every gate fails closed on missing markers, wrong fixture shape, nonfinite
  metrics, or capacity >256000000000 bytes /21600 seconds. A long execution
  lease never expands the capacity gate. No automatic promotion.

Our first cycle16 r1 controller **1159279** was retired only while queued, after
verifying exact PID/start/cwd, no children and no release log. It never ran a
release. `r1-retirement.json` and its frozen snapshot preserve the decision and
source. The r2 controller is a new snapshot, not a relaunch of r1 or any old
release. No original frozen driver was stopped or modified.

## Collect without duplicate launches

```sh
python3 integrator-evidence/cycle16-20260920/harvest.py --verify-source
./pod4 'cat /workspace/dsvert/executor-cycle16-lmm-release-r2/logs/progress.json'
./pod4 'tail -n 30 /workspace/dsvert/executor-cycle16-lmm-release-r2/logs/lmm-n4-k2-baseline.log'
```

Local watcher **49135** runs `harvest.py --watch`, detached stdin `/dev/null`.
`watch-launch.json` pins it. It stores source identities, stage-of-sequence,
release metrics/markers, bounded active log tails and full completed logs; full
source hashes are checked on terminal harvest or explicit `--verify-source`.
`latest.json` is the newest machine-readable record. Watcher does not promote.
Existing cycle12/cycle14 collectors are untouched.

On completion, review actual oracle/cold/tamper/recovery markers, source hashes,
measured aggregate-RPC bytes/time, and full paired CSV/RDS warnings/skips before
promoting. If K2 returns bitwise equality above six hours, retain the equality
proof but report capacity failure; do not call it a passing promotion release.
If the new path fails, preserve logs and diagnose that failure before any retry.
Do not reuse old-snapshot measurements as current-runtime evidence.

## Verified and unresolved

- Lease configuration is supported already. No production timeout limits,
  security checks, arithmetic, sticky-noise identity or native binaries changed.
- New release harness configures every fresh/cold peer before START and reports
  effective policies. Client negotiation of extended/shortest-peer leases passes.
- 11 lease-policy assertions PASS, including >6h liveness and >24h expiry using
  a controlled clock. Existing transport regressions: server325/client256
  assertions PASS; two server integration tests skipped by CRAN guard. These
  are focused tests, not full paired proof.
- Read-only old-binomial throughput sample shows ~290600 ACK payload bytes/s
  across a45s interval, little native CPU, no newly throttled cgroup periods.
  It is not LMM capacity and does not prove shared-transport contention.
- Cycle9 K2 reached `.exact_gc_expire_if_idle`; exact branch was sanitized and
  can be lost because abort deletes the private log's spool. Cycle15 exact
  six-hour operation-lease expiry is confirmed. See diagnosis for precise paths.
- Original LMM and binomial hashes reverified at01:36:05 UTC:2500/2526 match.
  LMM remains failed; original binomial K2 has194 COMMIT records and source
  Ring192 conversion active (unauthenticated progress only). No promotion.
- Cycle12 paired client remains active; previously passed server half stays
  tied to ba436a1/496c053. Queued Poisson remains on its original source/runtime.

No tags, pushes, thesis edits, simple-family releases or new math blockers.
