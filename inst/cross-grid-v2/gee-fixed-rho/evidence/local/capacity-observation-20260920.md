# GEE capacity, transport and resource observations — 2026-09-20

**Read-only investigation; promotion and n2000 capacity remain unproved.**
These observations do not record a completed DP release. No n2000 release had
started during the observation interval. No process, source, cap, setting,
snapshot, private record or seed was changed by this audit.

## Source identity and observation scope

The live job was Poisson GEE n4/C1/B4/p3/J2, K2, exchangeable rho=1/4,
epsilon=8, in `/workspace/dsvert/gee-fixed-rho-r4`. Its public frozen manifest
SHA256 is `1d4b78e617c85b7874d0b56c09f03977e1606a1b0b60e8869d2126e5427934df`.
The snapshot binds server `902ccf46d0f9b844155ff4316ac91cac2a2ba75b` and client
`6d94d4c9e15b9261a31b4499837d200ea1caea17`.

The worktree server commit at note preparation was
`a3964d39c26909d8f805f64cbfe2ad3a81b138b5`. Comparing its `R/` and
`inst/dsvert-mpc/` paths with `902ccf46` showed no differences. Harness and
checkpoint changes do not convert the r4 observations into r5 evidence.

Read sources were the job's public launch/log/resource records, `/proc` process
status/I/O counters, cgroup counters, operation marker existence, heartbeat
file modification times, numeric spool offsets, and stage-file names/sizes/
modification times. Private configuration, seed, stage-record and share
contents were not read. This note records interactive observations; it is not
a completed driver-generated capacity result.

## Live DP relay and resource observations

The Poisson driver PID was `2391186`; its two DP workers were `2496615` and
`2496655`. The paired server suite, PID `2391192`, was also active. The public
Poisson log had reached `dsvertDPSynopsisStartDS` after successful protected GEE
production. During the interval below, the DP operation had fresh heartbeats,
`ready` present, and no `done`, `error`, `failure.json` or `abort` marker.

All timestamps are UTC on 2026-09-20. Offsets are raw protocol bytes, not the
release gate's serialized aggregate RPC-byte metric.

| Time | Sender outbound head | Sender acknowledged offset | Receiver inbound acknowledgement |
|---|---:|---:|---:|
| 08:43:49 | 787,516,205 | 290,979,912 | 291,471,432 |
| 08:44:32 | 787,516,205 | 305,233,992 | 305,233,992 |
| 08:45:47 | 787,516,205 | 330,301,512 | 330,301,512 |
| 08:46:53 | 787,516,205 | 352,911,432 | 352,911,432 |
| 08:48:17 | 787,516,205 | 382,402,632 | 382,402,632 |

The sender acknowledgement advanced 91,422,720 bytes over 268 seconds:
approximately **341,130 raw bytes/second**. At the final sample, 405,113,573
bytes of that already-produced stream remained unacknowledged. Dividing by
the observed rate gives about 20 minutes for that remainder **if the rate
persists**. This is not a job-completion estimate: later protocol exchanges,
publication, oracle checks and replay are excluded. The first sample's one-
chunk acknowledgement difference is consistent with delivery preceding the
sender's next acknowledgement update; it is not a gap claim.

| Resource | Observation |
|---|---|
| Cgroup memory limit | 49,999,998,976 bytes |
| Cgroup historical peak | 50,000,031,744 bytes |
| Current usage at 08:43:20 | 19,880,882,176 bytes |
| Current usage at 08:48:17 | 20,330,881,024 bytes |
| `memory.failcnt` | 66 at every sample |
| `memory.oom_control` | `under_oom 0`, `oom_kill 7`, unchanged throughout |
| Worker 2496615, final RSS / historical HWM | 2,981,156 / 21,228,776 KiB |
| Worker 2496655, final RSS / historical HWM | 7,972,128 / 22,291,268 KiB |
| Container CPU quota / period | 765,000 / 100,000 microseconds: 7.65 CPU equivalents |

The workers' individual peak RSS values are approximately 20.25 and 21.26 GiB;
their peaks need not have occurred simultaneously. At the final sample both
workers were sleeping, relay activity continued, and heartbeat ages were under
four seconds. The evidence supports an active transport-throughput bottleneck
in this interval, not a stalled or dead worker. The container experienced
memory pressure and OOM kills at some earlier time, but its cumulative counters
have no event attribution or timestamps. **They do not prove that OOM caused
the failed binomial smoke.**

The separate binomial n4 public resource record reports exit 1 after
1,272.695861 seconds, maximum child RSS 11,830,076 KiB, and no successful proof
markers. Its old error handling did not establish the terminal worker cause.
That per-run child maximum must not be substituted for the observed live
Poisson workers' larger high-water marks.

Starting another sampler while these two remain live would undermine a serial
resource measurement. The completion condition suggested to the controller
was a final Poisson `.exit`/resource record plus disappearance of both DP worker
PIDs, rather than the current reduced RSS. The audit launched or stopped
nothing.

## Public graph scaling, not a measured n2000 result

Relevant source paths in the server repository:

- `inst/dsvert-mpc/k2_exact_gc_gee_source_staged.go:100`: source graph builder;
  cluster loop at line 175, candidate loop at line 228, final sum at line 257.
- `inst/dsvert-mpc/k2_exact_gc_gee_staged.go:61`: three arithmetic stages per
  cluster/candidate: factors, moments, terminal. Each also has its source eta
  stage; each cluster has shared feature and outcome stages.
- `inst/dsvert-mpc/cross_grid_grouped_route.go:113`: routing graph; 16-row
  normalization chunks at line 149 and switch tiling at line 189.
- `inst/dsvert-mpc/k2_exact_gc_cox_loss_shares.go:20`: 4,096-value OT batch;
  Beneš layers at line 24.
- `inst/dsvert-mpc/cross_grid_stage_executor.go:55`: sequential stage execution.
- `inst/dsvert-mpc/k2_exact_gc_gee_programs.go:16`: graph-local public program
  cache; reuse does not reuse secret execution, garbling, masks, OT or receipts.

For the present B4 cells, let `N=C*B`, `P=next_power_of_two(N)`,
`L=2*log2(P)-1`, `T=ceil((P/2)/floor(4096/(p+2)))`. For `P>1`, the graph has:

```
route_stages = ceil(N/16) + 2 + L*(T+1)
GEE_source_stages = 6 + route_stages + C*(2+4*J)
```

The fixed six comprise three source records, outcome normalization, source
lift and final sum. Routing contributes its chunk stages, normalized assembly,
each tiled layer plus layer assembly, and final output.

| Cell | Padded rows | Layers | Tiles/layer | Route stages | Complete source stages |
|---|---:|---:|---:|---:|---:|
| n4/C1/B4/p3/J2 | 4 | 3 | 1 | 9 | 25 |
| n2000/C500/B4/p3/J2 | 2,048 | 21 | 2 | 190 | 5,196 |
| n2000/C500/B4/p1 or p2/J2 | 2,048 | 21 | 1 | 169 | 5,175 |

The retained dev-r3 native proof logged 24 binomial and 21 Poisson cached public
programs per authority at C2/p3/J2. Those are measured counts for that fixture,
not an assertion that every cap/shape choice gives identical counts. Cache
reuse removes repeated public compilation; fresh cryptographic execution and
the sequential receipt protocol still occur for every cluster and candidate.
See the [retained native log](../dev-r3/logs/gee-native-focused.log).

For the live r4 Poisson job, both authorities had 25 stage files. On site A,
the first and final last-write times were 08:09:28 and 08:19:09 (site B final
08:19:10). Assigning stage intervals from their chronological order and the
known sequential 25-stage graph, without reading record contents, gives:

| Candidate | Factors interval | Moments interval | Terminal interval |
|---|---:|---:|---:|
| 0 | 08:12:27–08:14:14: 107 s | 08:14:14–08:14:48: 34 s | 08:14:48–08:15:37: 49 s |
| 1, public programs already cached | 08:15:43–08:17:28: 105 s | 08:17:28–08:18:02: 34 s | 08:18:02–08:18:50: 48 s |

These intervals include protocol/receipt/relay work and contemporaneous
contention; they are not isolated compute benchmarks. The near-equal candidate
intervals show that repeated compilation does not explain most elapsed time in
this run. Multiplying the approximately 412-second repeated cluster block by
500 gives approximately 57 hours under the same simplistic timing assumption.
**This is a warning projection, neither an n2000 measurement nor a lower
bound.** Concurrency, routing scale, serialization, cache warming and future
transport throughput can differ. It does not fill the capacity gate or justify
claiming a completed failure at n2000.

Reducing p3 to p1 at J2 changes the released vector including count from 43 to
15 coordinates; moment products per B4 cluster/candidate from 56 to 20; and
meat triangle products from 10 to 3. Nonlinear scalar profiles still execute
for every cluster/candidate. The existing genuine K5 harness assigns routing
to A, outcomes to B and covariates to C–E, and requires p>=3 at
`inst/cross-grid-v2/integrator-validation/validate_structured_dslite.R:271`.
A smaller-p cell therefore cannot replace that K5 evidence without changing
its source-owner scope. Native and signed R contracts accept J1, but the proof
harness requires J>=2 at line 32; singleton selection is also degenerate. No
cell or oracle commitment was changed.

## Why the proposed 8 MiB chunk setting was not adopted

`dsVert/R/exactGCTransportDS.R:237` allows a custodian chunk setting from 16 KiB
through 8 MiB, with default 480 KiB. The existing spool/request defaults at
lines 242/248 are 1 GiB and 64 MiB, and would remain valid at an 8 MiB chunk.
However, that is not the complete transport contract:

- `dsVertClient/R/dsi_fanout.R:122` sets the default complete-expression ceiling
  to 786,431 bytes; the negotiated geometry may supply the effective ceiling.
- `.dsvert_fanout_cycle` calls expression-size validation at line 1184 on every
  exchange before dispatching DSI requests.
- `dsVertClient/R/exact_gc_transport.R:589` accepts the server chunk range and
  line 647 requires the two peers' advertised chunk sizes to agree. Those
  checks do not override the separate expression ceiling.

A local, public-only synthetic `exactGCExchangeDS` expression was passed to
the actual client expression validator with its default ceiling:

| Raw chunk | Deparsed expression bytes | Result |
|---|---:|---|
| 480 KiB | 655,914 | PASS |
| 512 KiB | 699,606 | PASS |
| 8 MiB | 11,185,367 | `dsvert_resource_oversize` before DSI |

The existing server test `tests/testthat/test-exact-gc-transport.R:2405`
also documents why the default stays below the portable DSLite scalar limit.
Using the configured chunk maximum alone would therefore fail; raising or
bypassing the expression cap was rejected by this audit's unchanged-cap scope.
The 512 KiB check establishes size acceptance only, not a performance gain.

The minimal custodian configuration point, if a permitted geometry were later
measured, is the GEE branch of `structured_transport_policy` in
`validate_structured_dslite.R:43`, applied by its `we_boot_peer` wrapper at line
53 to fresh and cold peers. This was not edited. Small messages need not fill
the maximum chunk: `R/exactGCTransportDS.R:1926` waits at most the public
50-millisecond window (2-millisecond checks, constants at lines 16–17), then
returns available partial bytes. Pending deliveries disable long polling at
`dsVertClient/R/exact_gc_transport.R:1342`.

## Unchanged limits and suggested next work

No epsilon/delta, sensitivity, signed coordinate cap, 51-coordinate sampler
limit, 2,097,152-byte source cap, 524,288-bit input cap, 32,000,000-gate cap,
chunk setting, spool/request limit, expression ceiling or lease was changed.
The release gate remains 256,000,000,000 serialized aggregate RPC bytes and
21,600 seconds. Raw spool offsets are not interchangeable with that byte
metric. The 900-second inactivity and 86,400-second execution leases do not
relax the release gate.

The next useful evidence is a completed serial n4 run with the new harness
diagnostics, preserving actual worker failures and attribution where available.
Any subsequent n2000 job should retain the declared p3/J2 oracle and stop being
called a capacity success unless its measured gate passes. Further performance
work should first separate repeated stage/relay overhead from native arithmetic
using public counters and unchanged limits. It must retain fresh execution
cryptography, authenticated replay and sticky identity. Estimated correlation
and increases to shared transport caps are outside this work.
