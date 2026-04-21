# Structural diagnostic: Ring63 fracBits=25 breakage

Task #111 (redefined) root-cause investigation plan.
Codex audit 2026-04-19 late authorized 1-2h structural diagnose BEFORE
writing any migration patch. Goal: identify the hardcoded constant or
derivation that breaks when `K2DefaultFracBits` is bumped from 20 to 25.

## Observed symptoms at fracBits=25

| test | expected | observed | severity |
|---|---|---|---|
| Go `TestSoftmax_Composition` (K=4, n=20) | maxErr ≤ 0.02 | **3508** | catastrophic |
| R LMM synth balanced (intercept=99.45) | ~99.45 | **0.00** | catastrophic |
| Go `TestBeaverVecmulEndToEnd` | 1e-3 | 3.58e-8 | PASS (improves) |
| Go `TestWideSplineReciprocal_EndToEnd` | — | 0.013% rel | PASS |
| Go `TestWideSplineReciprocal_Clamps` | — | PASS | PASS |

Pattern: individual primitives work; composed pipelines (softmax =
exp + sum + recip + Hadamard; LMM = Beaver Gram + local-y) catastrophe.

## Prior hypotheses DISPROVEN

**Rejected**: uint64 overflow in `StochasticHadamardProduct`. `modMulBig63`
(k2_secure_exp.go:97) uses big.Int for all 128-bit products; no uint64
overflow in the multiplication path. `TruncateShare` uses `s/divisor`
with divisor ≤ 2^25, s ≤ 2^63 → quotient ≤ 2^38 fits uint64. No overflow.

**Rejected**: share-scale SNR boost (c=8 pre-multiplication). TruncMul
relative noise is 2^-fracBits INVARIANT under scaling — scaling does not
improve SNR. Confirmed empirically on LMM (regressed to |Δ|=3e-2).

**Rejected**: REML optim tolerance (LMM X4 gap at fracBits=20). Tightening
optimize(tol=1e-10) did not move the needle — confirming the gap is not
in the outer σ_b² search but in the Beaver-computed Gram.

## Candidate root causes (priority order per Codex)

### (a) DCF spline knot derivation assuming 2^20 scale — PRIMARY

The DCF wide-spline evaluates piecewise-linear approximations of exp,
reciprocal, log. Each spline has:
  - a domain `[lower, upper]`
  - `num_intervals` uniform sub-intervals
  - per-knot slope and intercept coefficients

If knot coefficients or the domain-to-interval index mapping is
derived implicitly from fracBits=20 (e.g., via integer arithmetic on
`int(x * 2^20)`), a bump to fracBits=25 would shift the indexing by
×32 and produce knots inconsistent with the intended function.

**Files to audit**: `k2_wide_spline.go` (all `Wide*Params` functions,
knot-generation routines), `k2_dcf_protocol.go` (spline Beaver-triple
generation and phase 1-4 orchestration), `k2_dcf.go` (raw DCF key
derivation).

**Diagnostic steps**:
1. Grep for literal `20`, `1<<20`, `1048576`, `2^20`, `<<20`, `>>20`
   in non-test `.go` files; log file:line of each hit.
2. Identify each hit as: (α) comment referring to 20 as documentation,
   (β) constant that SHOULD scale with fracBits (→ bug), (γ) constant
   that is intentionally fixed regardless of fracBits (→ OK).
3. For hits in (β) category, propose parametric fix in terms of
   `ring.FracBits` or `K2DefaultFracBits`.

Expected bisect outcome: one or two constants in `k2_wide_spline.go`
drive the knot positions or slopes; fixing them parametrically makes
the softmax test pass at fracBits=25.

### (b) k2-float-to-fp rounding accumulation at fracBits=25 — secondary

`FromDouble(x) = uint64(x * FracMul + 0.5)` where FracMul = 1 << fracBits.
At fracBits=25, the rounding threshold `0.5` is smaller relative to the
scaled magnitude. Accumulation of p×p Gram entries from 200 rows of
rounded FP encodes might drift differently than at fracBits=20.

**Diagnostic steps**:
1. Unit test: encode+decode a random float vector at fracBits=25 vs 20;
   verify max round-trip error is 2^-26 (half-ULP) vs 2^-21.
2. Analytic: round-trip error is BOUNDED by half-ULP, which at 25 bits
   is 32× smaller than at 20 bits. So this cannot explain a
   catastrophic error. LOW LIKELIHOOD; only examine if (a) is clean.

### (c) Other hardcoded fracBits=20 constants — catch-all

Observed hits from initial grep:
  - `k2_fp_ops.go:298` — `NewRing63(20)` in `handleK2FPSum` with comment
    "frac_bits doesn't matter for addition". Technically correct but
    should use `K2DefaultFracBits` for consistency. NOT a bug.
  - `k2_full_iter.go:225` — `NewRing63(20)` in `handleK2Ring63Aggregate`
    (context: frac_bits field defaulted). Bug if called without input
    frac_bits at mixed modes; already changed to use `K2DefaultFracBits`.
  - `k2_full_iter.go:350` — `NewRing63(20)` in another handler. Check
    and fix.

**Diagnostic steps**:
1. Exhaustive grep in all `.go` files (including `.go` with `_test`):
   patterns `NewRing63(20)`, `fracBits := 20`, `= 20$`, `<< 20`, `>> 20`,
   `1 << 20`, `2^20`, `2\\*\\*20`, `1048576`.
2. Categorise each hit (α/β/γ per above).
3. Fix all (β) hits to parametric form.

## Investigation workflow

1. **Grep pass** (15 min): list all hits in categories α/β/γ.
2. **Bisect test pass** (30 min): with fracBits=25 and the current
   parametric-by-design components (the majority per prior audit), run
   individual tests `go test -run TestWideSpline` → PASS; then
   `TestBeaverVecmul` → PASS; then `TestSoftmax_Composition` → FAIL.
   Identify which composition step first breaks.
3. **Minimal repro** (30 min): construct a minimal Go test that at
   fracBits=25 reproduces a measurable discrepancy on a single spline
   (exp at η=0.5, say), vs true math.exp(0.5).
4. **Fix + verify** (30 min): apply parametric fix to the identified
   constant; re-run the failing tests; iterate.

## Acceptance criterion for Task #111

**Ring63=25 unit tests green**: all Go tests pass including
`TestSoftmax_Composition` (threshold remains 2% per test line 399).

**LMM X4 rel<1e-4 STRICT**: on the canonical synth balanced scenario
(scripts/validate_cox_lmm_local.R §Scenario 5), X4 coefficient
relative error falls below 1e-4. 

**31 passed tasks re-validated**: no regression on any previously-
PASSed task. Table with pre/post |Δ|_abs, |Δ|_rel per task registered
in path_b_targets.md §Re-validation.

**Determinism probe**: across fresh R sessions, same seed, |Δ|<1e-10
(post-fracBits-25 floor will be tighter than current 3.3e-7).

**P3 compliance**: no new inter-server channels introduced by the fix.
DCF spline outputs remain share-level and reveal only the final
scalar aggregates per method.

## Rollback plan

If structural fix introduces regression on any Go test OR any R
package test that was passing at fracBits=20, rollback is trivial:
`git revert` the parametric-fix commit returns to fracBits=20
baseline. No dependent commits; no cascading rollback.

## Fallback (C) — iterative refinement

Authorized by Codex as ADAPTIVE safety net only IF structural fix
does not close LMM X4 rel<1e-4 after (a)+(b)+(c) are exhausted.
Activation conditions:
  - Structural fix shipped AND validated (all tests green at
    fracBits=25).
  - LMM X4 rel still above 1e-4 at fracBits=25.
  - 3-4h budget available in the same session.
Iterative refinement stacks ON TOP of the structural fix; NO rollback
of the structural improvement. P3 budget for refinement ≤2× baseline
scalar aggregates (see path_b_targets.md §LMM iterative-refinement
band-aid).

## What NOT to do

- Do NOT write a migration patch before identifying the root cause by
  name + file:line.
- Do NOT widen the 1e-4 relative target if the fix falls short — the
  target is the plan's acceptance bar, not a negotiation.
- Do NOT activate iterative refinement as a first option; it is a
  fallback to a failed structural fix, not a shortcut past the
  diagnose.
- Do NOT commit+push partially-working code; the green-gate at each
  commit is the discipline that prevents silent regressions.
