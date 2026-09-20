# Cycle16 lease and transport diagnosis

The exact-MPC lease **can be configured**. No math/protocol blocker is asserted.

## Which timeout failed

- Cycle15's harvested original LMM K2 failed in the client pump with
  `Exact MPC total runtime lease expired before both peers committed output`.
  This is the six-hour **operation** lease, not DSLite session age. The failed
  process took 24,745.135 seconds including bootstrap and other phases; it is
  not a successful release measurement. Both authorities retained 241 COMMIT
  records, with variance0 lift RUNNING (unauthenticated metadata only).
- `dsVert/R/exactGCTransportDS.R` reads administrator options
  `dsvert.exact_gc.max_runtime_seconds` (default 21600; maximum 604800) and
  `dsvert.exact_gc.ttl_seconds` (default 180; range 10..86400).
  The total must be at least the inactivity lease. `default.dsvert.exact_gc.*`
  is the fallback option namespace. New operations capture these policies.
- `dsVertClient/R/exact_gc_transport.R` validates the advertised policies and
  uses the shortest peer total/idle lease. Its local inactivity ceiling is
  `dsvert.exact_gc.timeout_seconds`, default 900. Verified worker heartbeats
  and byte/ACK progress renew inactivity, never the total deadline.
- Changing options after START does not renew an already captured server
  lease or the client's monotonic deadline. Configure before starting fresh
  transports. Existing durable stage recovery remains intact; no new automatic
  renewal/checkpoint mechanism was implemented in this cycle.
- `dsVert/R/mpcSession.R` separately uses a hard-coded 86400-second **session
  inactivity** constant. It is not exposed as an administrator option, but
  durable progress refreshes session activity; total session age is not capped.
  This is not the observed six-hour stopping condition.
- `dsVertClient/R/dsi_fanout.R` defaults the aggregate-job timeout to `Inf`
  (`dsvert.dsi.job_timeout_seconds`). The harness uses persistent isolated
  callr peers and distinct DSLite sessions, not HTTP transport through SSH.
  The SSH keepalive is therefore not the exact-MPC release lease.

## Cycle9: narrower conclusion than “transport contention”

Retained K2 log under cycle10/release-harvest/executor-cycle9-lmm-n2000-k2
shows site_b's `exactGCExchangeDS` failing with sanitized
`Exact MPC exchange failed`; its stop history reaches
`.exact_gc_expire_if_idle`. That function can reject malformed liveness state,
expired total/idle leases, or a dead worker. The retained evidence does not
identify which branch fired. Contract failures correctly remain fatal rather
than being blindly retried.

The code also explains why a precise private message can be absent: expiry
calls `.exact_gc_abort_state`, which deletes the spool, before the outer
`exactGCExchangeDS` error handler calls `.exact_gc_record_private_error`; that
logger returns without writing when the spool no longer exists. No missing
message is invented. Undated Gaussian-support errors are not the established
cause. The original failure and snapshots remain preserved.

Each existing release already boots its own callr/DSLite peer processes and
state directories. Concurrent drivers share pod resources, but there is no
observed shared connector/result slot between them. Cycle16 uses the explicitly
authorized isolated-transport option; new LMM/Poisson sequences also share one
exclusive flock. Legacy drivers are not stopped or altered.

## Read-only throughput observation

`transport-samples.json` records two public offset/process-counter samples from
legacy binomial K2, 45.002 seconds apart at 01:33:20–01:34:05 UTC. Both outbound
ACKs advanced by 13,077,616 bytes combined (~290,600 bytes/s). Selected client,
peer A/B and native A/B processes used 7.80, 13.51, 19.22, 3.71 and 4.07 CPU
seconds respectively; the paired client used 40.38 CPU seconds. Cgroup throttle
counters did not increase during this interval. This does not establish CPU
saturation or shared-transport contention as the cause. R transport overhead
and protocol waiting remain relevant; it is not a benchmark of the new LMM
path, not serialized aggregate-RPC capacity, and not a speedup prediction.

## Implemented release policy and proof gates

The synthetic signed-release harness applies **900-second inactivity /
86400-second total** administrator options after every isolated peer boot,
including cold boots, and prints the effective values and PID. The default
production policies and native arithmetic/runtimes are unchanged. The client
accepts these extended policies and still takes the shorter peer limits.

The new detached LMM sequence runs n4 K2, then n2000 K2, K3, K5, recovery,
then full paired suites. Every release has fresh peers and a distinct state
root. Source hashes are checked before each task. Later tasks stop on any
missing oracle/cold/tamper/recovery marker, malformed metric, or capacity
failure. The independent gate stays **256,000,000,000 serialized aggregate-RPC
bytes / 21,600 seconds**. A 24-hour execution lease is not 24-hour capacity
admission. No promotion is automatic.

Local checks: 11 server lease-policy assertions, including simulated passage
beyond six hours and expiry beyond 24 hours; explicit shortest-peer extended
lease negotiation and invalid-policy rejection; 325 server /256 client exact
transport assertions pass. Two pre-existing server integration tests were
skipped by their NOT_CRAN guard in this local run. No full-paired or n2000
claim follows from those tests.
