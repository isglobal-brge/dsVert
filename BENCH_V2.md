# V2 benchmarks — fused batch measured; full-release cost gate FAILS

## Latest: certified-cap fused source/loss batch

Both machines ran real encrypted two-authority Yao/KOS over net.Pipe, 32 rows,
p=10, eight distinct candidates with exact coefficient L1=4, A=4, g=16,
private source/validity/alignment checks and Ring128 masked candidate sums.
Binomial cap=263340; Poisson M=4 cap=3578149, from the accepted certificates.
One measured iteration; compilation is excluded from batch wall time.
Timing includes share preparation and the synthetic oracle comparison.
These are **source/loss batches, not authenticated DP releases**. Joint-noise
composition is tested separately and is not included in these traffic totals.

| Family | Exact AND/batch | AND/evaluation | Two-direction bytes/batch | Bytes/evaluation | Mac batch seconds | Pod batch seconds |
|---|---:|---:|---:|---:|---:|---:|
| Binomial | 1076415 | 4204.74609375 | 42404496 | 165642.5625 | 1.478935959 | 7.319170999 |
| Poisson | 1399391 | 5466.37109375 | 52745381 | 206036.64453125 | 2.308600250 | 7.605694722 |

Compilation: Mac 35.73 / 72.12 s; pod 177.5 / 222.3 s (binomial / Poisson).
Mac Apple M2; pod Xeon Gold 6342, GOMAXPROCS=8. Gate and byte counts agree
exactly. Single-iteration timings are observations, not throughput guarantees.
Raw logs: `inst/cross-grid-v2/fused-bench-{mac,pod}.log`.

### Deterministic full-size lower bound: FAIL

The frozen n=10000/grid=50 traversal contains at least
`floor(10000/32)*floor(50/8) = 1872` complete 32x8 batches. All 50 distinct
candidates can have the same exact L1=4 envelope/caps; public beta multiplication
is local, so changing their coefficient values does not change circuit topology.
Each AND transmits two 128-bit labels: **32 bytes of garbled table**. Therefore,
ignoring every tail batch, OT, input labels, framing, source transfer, joint
noise and release authentication:

| Family | Exact lower bound: 1872 * batch_AND * 32 | Binding 60 GB ceiling |
|---|---:|---|
| Binomial | 64,481,564,160 bytes (64.481564160 GB) | **FAIL** |
| Poisson | 83,829,118,464 bytes (83.829118464 GB) | **FAIL** |

This is a circuit-size lower bound, **not measured full-release traffic**. It
already rules out a <=60 GB execution of this compiled route at that public
workload. Parallelism and merely scheduling more small batches cannot remove
these tables. Binomial passes the <=5000 full-kernel AND/evaluation comparison;
Poisson does not. The earlier nonlinear-only components still pass that AND
comparison, but their favorable counts omit mandatory source/loss work.

Multiplying measured batch bytes by 500000 evaluations gives **projections**
of 82.821 / 103.018 GB, excluding joint noise and release transport. Serial pod
latency extrapolations are 238.25 / 247.58 minutes. Neither projection is a
completed full-release measurement or a parallel scheduling capacity claim.

**No n=2000 or n=10000 whole release has been executed. There is no measured
30-minute result. The requested n,p,grid full-release matrix is NOT DONE.**

A smaller *signed candidate set* preserves the current arithmetic certificate:
at grid=16, the same byte extrapolation is 26.503 / 32.966 GB before the remaining
release work. This is an illustrative reduction, not a measured/certified full
cost pass; it changes the requested grid and does not fix Poisson's full-kernel
AND count. Splitting the same 50 candidates into more batches does not reduce
total table bytes. A passing original-size route needs a materially cheaper
certified computation/transport design or a reviewed change to the resource
requirements; no unmeasured alternative is claimed to pass.

### Reproduction and provenance

From dsVert (equivalent small R driver: `Rscript inst/cross-grid-v2/benchmark_fused_batch.R .`):

```
cd inst/dsvert-mpc
go test -run '^$' -bench '^BenchmarkCrossGridFusedBatch$' -benchtime=1x -count=1 -timeout=0
```

Pod export/runner: `inst/cross-grid-v2/run_fused_pod.sh`, launched using
`./pod4` and nohup in `/workspace/dsvert/crossowner-v2/dsVert` after R_STACK_DONE.
The source hash verification for the timed pod snapshot is saved as
`fused-benchmark-source.sha256` and `fused-benchmark-source-check-pod.log`.
After that benchmark snapshot, an explicit rejection guard was added to the
ordinary compiler plus its focused test; further endpoint/slack regressions
were added afterward. These do not affect the specialized benchmark
path or any arithmetic/transport function used by it. Final source
verification and the focused suite are rerun separately on implementation
commit 2771a99 plus the final regression-test addition; the two snapshots are not mislabelled as byte-identical trees.
The Mac timed snapshot includes that guard. Numerical/profile/optimizer and
specialized runner sources used by both timed runs match.

Earlier fused stress-cap probes used cap=2^24 and duplicate candidates. Their
Mac logs are preserved as `fused-stress-cap-*`; they are exploratory, not the
basis of the certified-cap table or lower bound above. An old pod stress probe
was stopped after identifying that fixture issue. Historical component reports
below are retained with their original limitations.

---

# Historical component benchmarks — full release gate not measured

**Revised gate (reviewer Addendum 3): <=5000 AND/evaluation and <=60 GB measured
aggregate two-direction traffic for a full-size release, with pod elapsed time.
The historical 2000-AND/30-GB failure below is superseded.**

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

## Addendum 3: range-reduced exp and compact batched components

These replace the old Poisson arithmetic proposal and superseded cost verdict;
they still are **not the fused kernel or full-release benchmark matrix**.
K=64, batches of 32 nonlinear evaluations, real Yao/KOS and encrypted net.Pipe,
three measured iterations after calibration. The compiler runs outside timing.
GOMAXPROCS=8 on the pod. The Mac and pod use the same 464 Go source/module,
R/Python driver and JSON fixture files, verified by SHA256; see
`final-mac-source.sha256` and `final-pod-source-verification.log`.

| Component, compact batch32 | AND/eval (exact batch average) | Mac ms/eval | Pod ms/eval | Mac wire B/eval | Pod wire B/eval |
|---|---:|---:|---:|---:|---:|
| Binomial A4 | 2805.969 | 3.085 | 20.854 | 94036 | 94036 |
| Binomial A16 | 3077.969 | 3.087 | 33.419 | 102747 | 102747 |
| Range-reduced Poisson, A<=16 | 3540.969 | 4.647 | 28.204 | 117570 | 117570 |

The Poisson circuit is common across A; its certificate derives an error/cap
for each public A. Signed candidate-specific domain admission is not implemented.
The new binomial test container masks uint64 outputs, explaining ~33 more ANDs
than the old uint32 scalar component. No binomial polynomial changed.

Poisson framing/setup comparison (same polynomial):

| Batch / framing | Mac ms/eval | Pod ms/eval | Mac wire B/eval | Pod wire B/eval |
|---|---:|---:|---:|---:|
| 1 / legacy | 29.427 | 240.055 | 185177 | 185129 |
| 1 / compact | 25.835 | 269.290 | 136197 | 136173 |
| 32 / legacy | 2.665 | 32.406 | 166490 | 166490 |
| 32 / compact | 4.647 | 28.204 | 117570 | 117570 |

Compact framing authenticates a digest of the complete public topology and
omits per-gate row-length words. The existing production entry points always
retain legacy framing. Record encryption, garbling and KOS OT are unchanged.
Variation in random protocol framing and shared-machine scheduling remains;
three iterations do not establish a throughput guarantee.

### Whole-size projections only — gate remains unmeasured

Multiplying measured compact component bytes by 500000 gives 47.018 GB for
binomial A4, 51.374 GB for binomial A16 and 58.785 GB for Poisson. Poisson has
only about 1.215 GB left below the 60-GB limit for all additional work. These
projections exclude the complete f100 predictor, source/alignment transport,
outcome/log-factorial terms, loss clamping/reduction and joint DP release.
They **do not prove the full-release traffic gate**.

Multiplying the observed pod per-evaluation time by 500000 would give about
174 / 278 / 235 minutes respectively. These are serial component extrapolations,
not a measured release: fusion, signed row/candidate batching, reusable setup
and public-plan scheduling have not been implemented. **The requested largest
release has not been run; no measured >30-minute or <=30-minute result exists.**
Do not extrapolate these rows to a certified capacity claim or silently change
the ABI. The first cost-preserving integration is the frozen 32-row/8-candidate
batch, with per-candidate output masks/reduction rather than the test interface's
per-evaluation outputs. Any coarser precision would need a new certificate.

### Reproduction and evidence

```
# Mac, from dsVert:
Rscript inst/cross-grid-v2/benchmark_exp_reduced.R .
# Pod, from workspace, after exporting the matching tracked sources:
./pod4 'cd /workspace/dsvert/crossowner-v2/dsVert; nohup sh inst/cross-grid-v2/run_exp_reduced_pod.sh > /workspace/dsvert/crossowner-v2/logs/exp-reduced-run.log 2>&1 < /dev/null &'
```

Mac raw output: `inst/cross-grid-v2/exp-reduced-bench-mac.log`.
Final pod output: `inst/cross-grid-v2/pod-exp-reduced/exp-reduced-bench.log`.
The pod completion marker is `EXP_REDUCED_POD_DONE`. The same run passes the
certificate, R arithmetic/pooled checks and 14 Go top-level tests / 32 including
subtests with zero failures/skips. This is targeted verification, not a full
suite or R CMD check. Earlier partial pod logs were superseded after the
binomial batch and V1-exclusion cases were added; the final source hash check
covers all files used by the recorded final run.
