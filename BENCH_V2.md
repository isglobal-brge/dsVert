# V2 component benchmark — COST GATE FAILED

**The largest requested grid has NOT been run. There is no measured 30-minute
whole-grid result. No fused grid kernel exists in this change.** These are real
two-party measurements of a test-only nonlinear component, not completion of
deliverable 2. All 16 requested (n,p,grid,family) workload combinations remain
unmeasured.

K=64 piecewise quadratic; real Yao/KOS over encrypted net.Pipe; one input per
execution; 3 measured iterations after a calibration execution. Compile time
is excluded. Timings include fresh OT setup, range checking, share
reconstruction, masking and transport. Pod: Xeon Gold 6342, 96 vCPU; Mac: M2,
8 logical CPUs. Timings are observations on shared machines, not a capacity SLA.

| Family | A | AND/eval | Garbled table B/eval | Mac ms/eval | Pod ms/eval, default 96 | Pod ms/eval, GOMAXPROCS=8 |
|---|---:|---:|---:|---:|---:|---:|
| binomial | 4 | 2773 | 88736 | 29.291 | 332.881 | 268.405 |
| binomial | 16 | 3045 | 97440 | 29.781 | 368.567 | 392.765 |
| Poisson | 4 | 3346 | 107072 | 30.214 | 374.287 | 306.256 |
| Poisson | 16 | 4019 | 128608 | 30.441 | 398.193 | 269.237 |

Actual total wire bytes/evaluation (averaged over 3 executions):

| Family/A | Mac | Pod default | Pod GOMAXPROCS=8 |
|---|---:|---:|---:|
| binomial/4 | 144146 | 144145 | 144169 |
| binomial/16 | 155600 | 155650 | 155600 |
| Poisson/4 | 169489 | 169488 | 169489 |
| Poisson/16 | 198042 | 198058 | 198032 |

Both machines use Go 1.25.7. R is 4.5.2 on the Mac and 4.6.1 on the pod.
The raw logs include platform benchmark headers. Counts are identical
across platforms; `mac-source.sha256` and `pod-source.sha256` match. The copied
source corresponds to arithmetic commit `2ba2eba` (with the small benchmark R
driver staged separately). `R_STACK_DONE` was confirmed before pod execution.

## Public-size projection, NOT whole-grid measurement

Garbled-table payload alone for n=10000, grid=50, ignoring all other work:

| Family/A | AND gates | Payload, decimal GB |
|---|---:|---:|
| binomial/4 | 1386500000 | 44.368 |
| binomial/16 | 1522500000 | 48.720 |
| Poisson/4 | 1673000000 | 53.536 |
| Poisson/16 | 2009500000 | 64.304 |

This measured implementation misses both the 2000-AND target and the approximate
30-GB traffic target. Multiplying isolated-call latency by 500000 would give
hours, but is not a valid estimate of a batched fused kernel: fresh OT/setup
is paid for each test input. Predictor count has no role in this component
probe because the dot product is not included.

Batching can amortize setup and fixed framing; it cannot remove this circuit's
per-evaluation garbled-table payload. The certified A=4 binomial K=32 variant
slightly reduces ANDs to 2745 (43.920 GB projected), still failing the target.
For full-domain Poisson, reducing K also sharply increases the interpolation
error. No measured candidate currently satisfies the combined cost and utility
gates, so no cheaper *jointly acceptable certified* replacement is claimed.

The next arithmetic experiment should evaluate range reduction for exp and
symmetry for softplus, or an authenticated arithmetic-share implementation
with certified exact truncation. Those require new certificates and protocol
measurements. No ABI change, weaker privacy default, larger cap admission or
trusted preprocessing shortcut has been made to hide the failed gate.

## Reproduction

From dsVert:

```
Rscript inst/cross-grid-v2/benchmark_profile.R .
# Equivalent Go benchmark:
cd inst/dsvert-mpc
go test -run '^$' -bench '^BenchmarkCrossGridPWV2Protocol$' -benchtime=3x -count=1
```

Pod launch from the workspace used the required wrapper and dedicated directory:

```
./pod4 'cd /workspace/dsvert/crossowner-v2/dsVert; nohup Rscript inst/cross-grid-v2/benchmark_profile.R . > /workspace/dsvert/crossowner-v2/logs/bench-pod.log 2>&1 < /dev/null &'
./pod4 'cd /workspace/dsvert/crossowner-v2/dsVert; nohup env GOMAXPROCS=8 Rscript inst/cross-grid-v2/benchmark_profile.R . > /workspace/dsvert/crossowner-v2/logs/bench-pod-procs8.log 2>&1 < /dev/null &'
```

Evidence is in `inst/cross-grid-v2/bench-{mac,pod-default,pod-procs8}.log`.
