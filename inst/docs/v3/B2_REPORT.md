# v3impl03 — B2 implementation and validation report

2026-10-15. B2 is implemented and its targeted checks pass. This is ready for
the maintainer Claude session's review; it is not that session's approval or
the B3 R/DSI performance gate. The Phase A and accepted B1 reviews were read.
No `claude` CLI, push, full suite, live federation, or 1.4.2 runtime write was
performed. The design remains SHA256
`f67bdabbb8b2b6fdda36b8062c5e7e5e85a064bba3905c256f5e6e543b08aa9b`.

Only the server v3 worktree changed, on `feature/v3-dp-irls`; the client v3
worktree remains unchanged and clean on the same branch. Builds used the
isolated env and `.tmp/v3/bin`. The final `dsvert-mpc` SHA256 is
`c9646f90e5be50820183d3e570554ed66b46887312e782bd5305197e5818f72a`.
Development version remains 1.5.0.9000. Both worktrees are clean.

## Commits

All server commits carry
`Claude-Session: https://claude.ai/code/session_014vmGJDh1R1RPiYA7iGUK1G`.

| Commit | Change |
|---|---|
| `e885fc4` | Fused public-point producer and cross-grid kernel seams |
| `0ff9a9c` | Numeric certificate, rational proof and R/Go fixtures |
| `1291218` | Signed profile and authenticated B1 point admission |
| `1ff202a` | Avoid compiler signed-literal defects; clamp regression |
| `662c173` | Independent integer oracle, exactness and sensitivity witnesses |
| `c002f54` | Noiseless B1 iterations and independent R glm comparison |
| `10027e7` | Negative fixed-intercept regression |
| `7917c24` | Durable executor binding, real two-party tests and timings |
| `57c8701` | B2 boundary and B3 admission documentation |

## Producer and admission

`R/dpIRLSProfile.R` verifies the unanimous B1 contract signatures and exact
numeric profile. `.dsvert_dp_irls_stage_plan` opens the durable B1 store,
verifies the predecessor chain, recomputes prior updates, and derives beta_t.
It rejects another beta, predecessor, uncommitted successor or score-only
stage. R-generated authenticated point fixtures agree byte-for-byte with Go.

`k2_dp_irls_stage.go` binds beta, root, stage ID/index, predecessor, purpose,
family, shape, intercept/offset modes and certificate into the kernel purpose.
The point has exact q16 integer coefficients. The ordinary GC compiler and
public cross-grid plan handler reject this internal operation. Go checks the
point/certificate bindings; B1 signature/history verification lives in R.
B3 must preserve this authenticated-constructor boundary rather than expose
an unsigned Go-plan endpoint.

The producer reuses `crossGridKernelPrivateInput`, `crossGridKernelSource`,
`crossGridKernelCompile` and `runWithSeed`, plus the pinned grouped link
arithmetic. It reconstructs Ring128 shares inside GC, applies source clamps,
forces a signed intercept or absent offset where declared, rounds/clamps eta,
evaluates sigmoid/exp, and produces x*r and the row-major upper triangle
w*x*x'. Both lanes and one masked validity bit come from the same circuit.
Each signed person slot has one row; absent slots contribute exactly zero.
Each person's coordinates are rounded once, reduced, and translated once.
Only nine aggregate additive shares and shared validity leave the circuit.

`k2_dp_irls_executor.go` checks that the prepared point generates the exact
durable graph before calling `crossGridStageExecutor.Execute`. One private
COMMIT contains both lanes. Fresh attempts use private output masks; retained
COMMIT replay returns identical shares. There is no aggregate-opening command,
noise-off switch, R/DSI method or public publication path. Mandatory split noise
and publication are B3/B4 work.

## Frozen numeric certificate

Profile `dsvert-dp-irls-producer-p3-q16-q12-v1`: two owners, p=3,
n=C=1..64, row_cap=1. Other dimensions, larger capacities and repeated rows
reject. X and beta are q16 in [-1,1], with x0 forced to 1 for an intercept.
Explicit offsets are q16 in [-1,1]; absent offsets are forced to zero. The
complete predictor is rounded nearest-even to q16 and clamped to [-4,4].
Bernoulli outcomes are 0/1; malformed outcomes mask that person's contribution.
Poisson integer outcomes clamp to [0,8]. Presence/missingness stays protected.

Sigmoid mu clamps to [0,1], r=y-mu, and w is the q16 nearest-even value of
mu*(1-mu), clamped to [0,1/4]. Poisson mu clamps to [1200/65536,55], r=y-mu,
w=mu. The pinned link manifest is
`f72e66abaf2e503a809f23d4563418d2889843174109398ae48b02f0ec7edb84`.

| Certificate quantity | Binomial | Poisson |
|---|---:|---:|
| Uniform link error at q16 eta | 69/327680 | 11/2000 |
| Physical score-coordinate error, including eta and q12 rounding | 877/2621440 | 98987/16384000 |
| Physical H-coordinate error, including weight rounding | 897/2621440 | 98987/16384000 |
| Person integer caps g / H | 4096 / 1024 | 225280 / 225280 |
| Add/remove S1_g / S1_H | 12288 / 6144 | 675840 / 1351680 |
| Replace-one S1_g / S1_H | 24576 / 12288 | 1351680 / 2703360 |
| A_g / A_H at C=64 | 262144 / 65536 | 14417920 / 14417920 |

Output lattice is 2^-12; beta lattice is 2^-16. Person rounding L1 slack is
3/8192 for g and 3/4096 for H. The tighter integer cap proof uses monotonic
nearest-even rounding with integral endpoints; it does not discard rounding
slack. A_j=C*cap_j exactly, U_j=2*A_j, with zero extra translation margin.

Eta rounding error is <=2^-17. The maximum exact q32 dot is 4*2^32, raw
score <=55*2^32, and raw H <=55*2^48<2^54. Even a hypothetical 64-row raw-H
sum fits below 2^60. All post-clamp deterministic arithmetic fits signed64;
translated q12 sums are below 2^25, with Ring128 masks. Raw input residues
are handled across the full signed128 range before narrowing. The full n=64
typed input is 100608 bits, below the existing 524288-bit guard; both measured
circuits are below the 32-million-gate guard.

The proof script `inst/certificates/dp_irls_b2_certificate.py` checks 130 link
knots with rational enclosures, analytic interpolation/reduction errors,
rounding, all 64 capacities and range inequalities. Source conversion from
original real values is not included: B3 must certify its materialization.
Curvature is explicitly a preconditioner, and sampling inference remains
unqualified. Details are in `inst/docs/dp_irls_producer_b2.md`.

## Exactness, sensitivity and iteration results

All final checks pass; the earlier compiler mismatches described below were
corrected. No timeout was treated as a pass.

* **1302** protected `Circuit.Compute` evaluations equal the independent
  big-integer oracle: 148 random/boundary evaluations, 26 intercept/offset
  and negative-intercept cases, and 1128 sensitivity-witness states.
  These check **11718** score/H coordinates and **1302** validity bindings.
  Coverage includes random fractional source coordinates, mixed-sign public coefficients,
  offsets, all-absent and zero-design rows, malformed inputs, Ring128 extrema,
  both alignment-failure forms and nearest-even arithmetic. The 148-case
  portion processes 592 rows, including four all-absent evaluations.
* **94488** neighboring-input comparisons cover coordinate corners and
  residual/weight extremes: 13284 binomial and 81204 Poisson.
* Four real Yao/KOS-checked OT executions pass: one n=64 stage per family
  plus two n=1 executor checks. All 36 aggregate-coordinate comparisons pass.
  All four retained-share replays and four alternate-point-before-I/O
  rejections pass. Only the synthetic test harness reconstructs shares.
* R B2 admission: 3 cases, 43 assertions. Existing B1 R: 13 cases,
  518 assertions. Go certificate/ABI: 3 tests, 128 admitted family/shape
  combinations, 9 rejection cases, two certificate and two signed-point
  byte fixtures. Producer: four focused tests including nine Ring128 clamp
  extrema. Existing affected tests: 19 core GC tests, all ten kernel tests,
  and two durable-worker/mask tests pass.

| Witness | Realized max g / H | Declared g / H |
|---|---:|---:|
| Binomial add/remove | 12066 / 6144 | 12288 / 6144 |
| Binomial replace | 17964 / 6144 | 24576 / 12288 |
| Poisson add/remove | 670920 / 1341840 | 675840 / 1351680 |
| Poisson replace | 699592 / 1341840 | 1351680 / 2703360 |

The oracle is test-only and parses committed knot constants independently;
it does not call the producer, grouped link evaluator or source generator.
Finite witnesses supplement the algebraic certificate, rather than prove it.

For n=64 interior fixtures, 12 actual B1 Go updates on oracle sums reach a
zero terminal integer score without stabilization, trust truncation,
projection or saturation. Independent R `glm()` comparisons give:

| Family | Endpoint L2 error vs glm | Separate exact-link finite-T error | Certified numeric radius |
|---|---:|---:|---:|
| Binomial | 0.000530922107608 | 6.85275e-15 | 0.0370851698789 |
| Poisson | 0.0000761186714482 | 2.35514e-16 | 0.6697285675345 |

The radii are conservative bounds from the signed coordinate-error envelope
and the exact whole-box proof H>=I for these fixtures. They are not empirical
tolerances or statistical confidence intervals. Finite-step error is computed
using the same public update settings with exact links and no lattice rounding.

## Real two-party component timings

Each family ran in a separate `nice -n 10 timeout 14m` command over `net.Pipe`,
using the real encrypted-record Yao/OT path and private durable stores. Public
beta was (1/4,-1/8,1/16), with three explicit X coordinates and bounded offsets.
The net.Pipe fixtures are synthetic; signed R/B1 admission is checked separately
by the ABI tests. These measurements include no R/DSI lifecycle.

| Component, seconds unless stated | Binomial n=64 | Poisson n=64 |
|---|---:|---:|
| Circuit compile/optimization | 33.937045 | 33.582225 |
| Garble | 1.782019 | 1.472227 |
| Garbler table/input transfer | 0.990252 | 0.545896 |
| OT sender | 0.135926 | 0.098849 |
| OT receiver | 0.137106 | 0.100579 |
| Evaluate | 0.437554 | 0.412950 |
| Private durable stage wall, compile excluded | **5.195649** | **4.048709** |
| Wire bytes, both directions | 94792856 | 97583481 |
| Total gates / AND gates | 9629846 / 2859863 | 10095126 / 2947019 |

OT role durations overlap and must not be added together. Stage wall also
includes context hashing, packing, encrypted framing and durable executor
bookkeeping; it is not just the sum of the named components. Compilation is
measured separately. Go binary build, source materialization, PSI, production
key agreement/signatures, both DP noise lanes and publication are excluded.
The complete binomial/Poisson test commands took 39.14/37.63 seconds.

Single-point linear extrapolation (component * n/64), **not admitted shapes,
benchmarks, bounds or R/DSI forecasts**:

| Family, n | Compile s | Garble s | Transfer s | OT max s | Evaluate s | Private stage s | Wire MB |
|---|---:|---:|---:|---:|---:|---:|---:|
| Binomial, 200 | 106.053 | 5.569 | 3.095 | 0.428 | 1.367 | 16.236 | 296.228 |
| Poisson, 200 | 104.944 | 4.601 | 1.706 | 0.314 | 1.290 | 12.652 | 304.948 |
| Binomial, 1000 | 530.266 | 27.844 | 15.473 | 2.142 | 6.837 | 81.182 | 1481.138 |
| Poisson, 1000 | 524.722 | 23.004 | 8.530 | 1.572 | 6.452 | 63.261 | 1524.742 |

Compiler/memory scaling and network contention need actual measurements for
larger shapes. B3's <=240-second complete-stage gate remains untested.

## Commands, evidence and deviations

All runtime commands source `/workspace/dsflower/.tmp/v3/env.sh`. Targeted
commands use `nice -n 10 timeout 14m`; explicitly retained binaries are built
only in `.tmp/v3/bin`. Go-managed temporary test/build artifacts use the
isolated v3 environment. No full suites were run. Representative commands:

```sh
# From v3-dsVert/inst/dsvert-mpc, after sourcing the env:
nice -n 10 timeout 14m go test -c -o /workspace/dsflower/.tmp/v3/bin/dsvert-mpc-b2.test .
nice -n 10 timeout 14m /workspace/dsflower/.tmp/v3/bin/dsvert-mpc-b2.test \
  -test.run '^(TestDPIRLSB2CircuitExactness|TestDPIRLSB2SignedInterceptAndOffset|TestDPIRLSB2IntegerSensitivityWitness)$' -test.v -test.timeout=13m
nice -n 10 timeout 14m /workspace/dsflower/.tmp/v3/bin/dsvert-mpc-b2.test \
  -test.run '^TestDPIRLSB2RealTwoParty64/binomial$' -test.v -test.timeout=13m
nice -n 10 timeout 14m /workspace/dsflower/.tmp/v3/bin/dsvert-mpc-b2.test \
  -test.run '^TestDPIRLSB2RealTwoParty64/poisson$' -test.v -test.timeout=13m
DSVERT_B2_ITERATION_OUTPUT=/workspace/dsflower/.tmp/v3/b2-iteration-evidence.json \
  nice -n 10 timeout 14m /workspace/dsflower/.tmp/v3/bin/dsvert-mpc-b2.test \
  -test.run '^TestDPIRLSB2NoiselessIteration$' -test.v -test.timeout=13m

# From v3-dsVert:
nice -n 10 timeout 14m Rscript tools/test-dp-irls-b2-iteration.R /workspace/dsflower/.tmp/v3/b2-iteration-evidence.json
PYTHONDONTWRITEBYTECODE=1 nice -n 10 timeout 14m python3 inst/certificates/dp_irls_b2_certificate.py
```

Logs are `.tmp/v3/B2-real-binomial.log`, `B2-real-poisson.log`,
`B2-executor-small.log`, `B2-core-regression.log`, and
`.tmp/v3/tmp/b2-{kernel-regression,frozen-shape,worker-regression}.log`.
`B2-R-regression-summary.log` explicitly records commands and observed results
as a transcript summary, not raw redirected stdout. The main oracle run took
about 18.15 seconds; its extra negative-intercept regression took 0.67 seconds.
The longest focused existing regression was 165.92 seconds.

Independent exactness exposed two pinned-compiler defects: signed int128
comparison against a negative literal, and negative literal widening to
int64. The producer now uses unsigned Ring128 sign/magnitude clamping and
subtracts positive public-beta products. The compiler was not changed;
fractional-coefficient and extreme-value regressions cover both workarounds.

Conservative restrictions and B3 questions are also in `B2_QUESTIONS.md`:

* One row/person and C<=64 only; no tiles or repeated-person aggregation
  beyond that admitted case. p=5/10 and n=200/1000 need new admission evidence.
* B3 must authenticate source/slot provenance and materialization, carry
  validity privately, and preserve personwise masking. Public validity or
  whole-vector zeroing after one malformed row is outside this sensitivity
  proof. Any finite validity/conversion law needs its own privacy admission.
* Add the named smoke profile only with its complete frozen schedule, then
  reuse these numeric constants. B2's numeric profile ID is not a blanket
  alias for `irls-smoke-k2-c64-p3-v1`. Showcase still needs the accepted public
  simulator selection and refusal pre-check, and any larger shape certificate.
* Implement mandatory split noise, atomic publication and the thin R/DSI
  route, then measure the complete <=240-second stage. A failed gate still
  stops promotion for a maintainer decision. No sampling-inference or live
  federation qualification is claimed by this B2 result.
