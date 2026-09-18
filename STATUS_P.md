# Primitive V status

Branch: `feature/oblivious-grouping` in both checkouts. Base dsVert `4d7e6ae`.
No pushes, thesis edits, client changes, or step-1 ABI changes. The implementation
is an internal library and worked circuit specification, not release promotion.
See [PRIMITIVE_V.md](PRIMITIVE_V.md) for contracts, proofs, integration and costs.

## Milestones

1. Existing exact categorical, Gaussian cross and sealed GC routes, source
   transport, and frozen numeric contract inspected. `STATUS_V1.md` was absent;
   `DECISIONS_V1.md`, `NUMERIC_CERTIFICATE_V1.md`, the machine profile,
   `cross_grid_contract_v1.go`, and `CROSS_OWNER_DESIGN_CODEX.md` were available.
2. Existing Yao/checked OT/encrypted-record protocol reused for native192 outputs.
   Independent fresh masks cover loss and private validity. Generated source
   and the caller-verified signed contract are bound to the session. `2022095`.
3. Beneš routing/emitter, padded vectors, deterministic switch model, exhaustive,
   random and compiled equality tests. `a320868`.
4. Additive q64 exp/log profile, segmented and prefix reductions, rational error
   certificate and independent accuracy tests. `caa9b2b`, `543b6a6`, `a5cddb2`.
5. Cox Breslow, LMM, and binomial GH5 GLMM worked circuits, independent integer
   references, private validity, caps and DP proof notes. `8373281`, `af34111`.
6. Bounded compilation/preflight, synthetic encrypted benchmarks, permanent LMM
   protocol test, and compiled signed-shift tie fixtures. `4b5c1a8`, `33daa5c`.
7. Mac/pod costs recorded; final full-package verification detailed below.

Only `k2_exact_gc_core.go` changes among pre-existing production files: it admits
an internal session operation and rejects that operation in the generic compiler.
The frozen cross-grid ABI/profile, R methods and dsVertClient are unchanged.

## Verification and reproducible commands

Run from `dsVert/inst/dsvert-mpc` (Go 1.25.7; pinned MPCL
`v0.0.0-20260325113446-c911bbd029d1`):

```sh
go test -run '^TestPrimitiveV' -count=1 -json -timeout=15m .
PRIMITIVE_V_BENCH=1 go test -run '^TestPrimitiveVMeasuredCosts$' -count=1 -v -timeout=15m .
go test -run '^$' -bench '^BenchmarkPrimitiveVPermutation' -benchtime=1x -count=1 .
go test -run '^(TestExactGCSecureRecords|TestExactGCAlignmentMask|TestExactGCAlignmentMismatch|TestExactGCCategoricalProduct|TestCrossGrid)' -json -count=1 -timeout=10m .
```

| Check | Result | Scope |
|---|---|---|
| Existing Mac regressions | 20 top-level + 16 subtests passed; 0 failed/skipped; 24.504 s | Frozen encoding/profile and integer references, private alignment, exact categorical product, secure records/tamper/replay |
| Pod primitive suite, dependency closure | 20 top-level + 15 subtests passed; 0 failed; 1 opt-in benchmark skipped | All three compiled families, arithmetic certificate, numeric accuracy/ties, reductions, permutation and actual encrypted protocol |
| Mac synthetic microbenchmarks | 1 top-level + 7 operation subtests passed; 29.16 s | Actual encrypted two-party local transport |
| Pod synthetic microbenchmarks | 1 top-level + 7 operation subtests passed; 5.59 s | Same circuits and gate/table counts |
| Pod full tracked package build | Passed; 83 wall s | Ordinary `go test -c` against all tracked Go files at `33daa5c` |
| Pod full tracked primitive suite | 20 top-level + 15 subtests passed; 0 failed; 1 opt-in skip; 109.807 s | Ordinary module command above; 129 s command wall time; empty stderr |

The durable [validation summary](inst/primitive-v/validation.json) records test
names, counts, commands and log hashes. The opt-in benchmark skip in the general
suite is intentional; it was run
separately with its environment flag on both hosts. Initial Mac full-package
protocol checks also passed (2 top-level, 1.782 s). The whole multi-hour Go
suite and the R suites were not run; no R source changed.

Permutation coverage: 46,233 exhaustive permutations through n=8, 108 random
padded instances through n=10,000, and 112 compiled equality fixtures across
seven shapes. Numeric checks include 54 compiled signed /2 and /64 tie/boundary
fixtures, an independent high-precision accuracy oracle, rational inequalities
for the certificate, and 10,000-term lower-endpoint prefix accumulation. Family
checks cover Breslow tie endpoints, rho=0/reference targets, private permutation,
private boundaries, inactive rows, cap failures, and masked validity. A permanent
two-row LMM test passes through the existing encrypted garbler/evaluator protocol.

To avoid repeatedly compiling the large package during development, synthetic
benchmarks also used a temporary Go AST dependency-closure harness: 159 required
production declarations copied verbatim across 27 Go files, without protocol
stubs. Source SHA256 values are recorded with the costs. The full tracked
package build and final ordinary suite additionally check package integration.

## Measurements and interpretation

Machine-readable observations: [Mac](inst/primitive-v/costs_mac.json) and
[pod](inst/primitive-v/costs_pod.json). Inputs were public synthetic fixtures;
protected values and protocol shares were not logged. Gate/table counts are
deterministic. Protocol times use local encrypted `net.Pipe`, not inter-host RTT;
wire bytes include only the garbler direction. `heap_sys_bytes` is cumulative
Go heap reservation, not peak RSS.

Mac: Apple M2, arm64, 16 GiB RAM; Go 1.25.7 darwin/arm64. Concurrent project
workloads heavily contended compilation. Routing n=10,000 took 8.956792 ms,
5,097,664 bytes and 12,800 allocations. Compiling the n=32, d=3, w=192 network
took 7.863869 s and 550,215,648 allocated bytes. The complete Cox/LMM fixtures
passed; their compile times were 100.964 s and 119.456 s. A duplicate Mac GH5
compile was interrupted after the identical circuit passed on the pod; no
completed Mac GH5 or full Mac suite timing is claimed.

Pod: Intel Xeon Gold 6342 at 2.80 GHz, 96 logical CPUs, 540,644,081,664 RAM bytes;
Go 1.25.7 linux/amd64. CPU GC only; no GPU used. Routing n=10,000 took 10.034923 ms,
5,102,976 bytes and 12,804 allocations. The same n=32 network compiled in
0.902511 s with 550,699,448 allocated bytes. Small full family compile costs:
Cox n=2, 3,831,103 gates / 2.223 s; LMM n=3 padded to 4, 5,082,865 gates / 2.759 s;
GH5 n=2, 28,020,152 gates / 20.433 s. These are compilation/equality checks;
protocol measurements are separately labeled in the cost artifacts.

The n=10,000, p=10, grid=50 family costs are analytical component-call models
using measured microcircuits, plus the permutation model. No full-scale encrypted
run was attempted or claimed. Fixed public resource limits reject a monolithic
request before protected input access. Deployable full-scale family consumers
need a signed chunk/streaming schedule and arithmetic optimization; the current
code supplies reusable emitters, exact worked specs and bounded protocol runs.

## Pod readiness and provenance

The supplied launcher initially had an empty endpoint. Once it became available,
`./pod4` was used to observe `/workspace/logs/install_r.log`. Tests and benchmarks
started only after `R_STACK_DONE` appeared; the temporary endpoint issue is
resolved and is not a blocker. No pod creation or reconfiguration was performed.

Synthetic verification directory:
`/workspace/dsvert/primitive/verification-20260918T120404Z-ba9421`.
Harness archive SHA256:
`dc4a57697c5ec1c4b6ab213da16d7e99f6ca0929a77e2e1ca5d53fcb33cee80e`.
Full tracked checkout directory:
`/workspace/dsvert/primitive/fullrepo-33daa5c-2a710a/code`.
Full tracked archive SHA256:
`e384c55635d9d887d08b992a5afd1d17fe384a4f4bd1b445eb18ecb8a1b39db5`.

Local task logs are in `/tmp/primitive-v-results/`: `regression.jsonl`,
`mac-microbench.txt`, `pod-microbench.txt`, `pod-permutation-bench.txt`,
`pod-suite.txt`, `pod-hardware.txt`, `pod-full-suite.json`,
`pod-full-suite-time.txt`, `pod-full-build.txt` and `pod-full-build-time.txt`. Durable cost artifacts retain source
hashes, hardware, timings, deterministic counts and scope limitations. All
remote work is isolated under the requested `/workspace/dsvert/primitive` path.
