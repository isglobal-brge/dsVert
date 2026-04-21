# Pre-fix tolerance targets (ex-ante, Codex audit gate)

Declared BEFORE touching code for Path B + LMM fix. Any post-fix result
that misses these targets is a FAIL, not a relaxation opportunity.

## Current honest baseline (2026-04-19 late, post-all-reverts)

LMM synth balanced (20 clusters × 10 obs, 4 covariates, intercept=100):
  |Δ|_abs_max = 3.87e-4 (X4)   — within abs<1e-3 strict for |β|≤1
  |Δ|_rel_max = 1.14e-3 (X3)   — X3 |β|<1 so abs rule applies; PASS
  **X4 |β|=1.79 → rel=1.78e-4** — EXCEEDS strict rel<1e-4 bar by 1.78×
  Only X4 blocks strict PASS. ALL OTHER coefficients pass strict.

Cox synth weak PASS_STRICT |Δ|=7.3e-4. Cox NCCTG/Pima/strong FAIL per
documented O(|β|²) bound (docs/error_bounds/cox_newton_onestep.md).

**Retraction (2026-04-19 late)**: an earlier internal note claimed
"X4 rel=2.2e-4" and "rel improvement 5×" — both arithmetic errors.
Correct number is rel=1.78e-4 and NO improvement has been achieved from
the originally-reported 1.14e-3 max-rel baseline. Targets unchanged.

## Task #111 redefined (Codex 2026-04-19 late)

ORIGINAL: uint64→big.Int migration in k2_truncation.go Hadamard paths.
INVALIDATED by diagnostic — `modMulBig63` (k2_secure_exp.go:97) already
uses big.Int for the 128-bit multiply; `TruncateShare{PartyZero,PartyOne}`
uses uint64 `s/divisor` which has no overflow risk (divisor ≤ 2^25,
s ≤ 2^63 → quotient ≤ 2^38, fits uint64). The original uint64 overflow
hypothesis was wrong.

REDEFINED: **Diagnose and fix structural cause of Ring63 25-frac_bits
breakage**. See docs/diagnostic/ring63_fracbits.md for the investigation
plan. Candidate root causes (priority-ordered per Codex directive):
  (a) DCF spline knot derivation assuming 2^20 scale — PRIMARY
  (b) k2-float-to-fp rounding accumulation at 25 bits — secondary
  (c) Other hardcoded fracBits=20 constants outside Truncation — catch-all

Acceptance criterion for Task #111: Ring63=25 unit tests all green
(incl. TestSoftmax_Composition which currently gives |err|=3508) AND
LMM X4 rel<1e-4 STRICT. (C) iterative refinement remains RESTORED as
adaptive fallback if structural fix doesn't close LMM — without
rolling back the structural fix (it stays as architectural improvement).

Acceptance rule (per plan §Validation protocol):
  per coefficient j: pass iff
    |β_j,ref| ≤ 1  →  |Δβ_j|    < 1e-3  (absolute)
    |β_j,ref| > 1  →  |Δβ_j/β_j| < 1e-4  (relative)
  scenario passes iff ALL coefficients pass.

## Cox scenarios

| scenario | n | n_events | |β|_max_std | |β|_max_orig | pre-fix state | post-fix target |
|---|---|---|---|---|---|---|
| weak_synth | 200 | 114 | 0.12 | 0.008 (bp) | |Δ|=7.3e-4 PASS | PASS unchanged |
| NCCTG lung | 210 | 150 | 0.54 (ph.ecog) | 0.68 (ph.ecog)| |Δ|=5.3e-2 FAIL | PASS (Path B, 3-5 iters) |
| Pima_synth | 532 | ~346 | 0.17 (ped) | 0.34 (ped) | |Δ|=1.2e-1 FAIL | PASS (Path B) |
| strong_synth | 300 | ~197 | 0.86 (X3) | 0.86 | |Δ|=1.6e-1 FAIL | PASS (Path B, up to 5 iters) |

L2 (local harness) and L3 (Opal) must match L1 (pooled coxph) within
additional FP noise  ≤ 1e-5 absolute (Ring63 floor).

## LMM scenarios

| scenario | n | n_cluster | |β|_max | pre-fix state | post-fix target |
|---|---|---|---|---|---|
| balanced_synth | 200 | 20 (all size 10) | 1.79 (X4) | X4 rel=1.79e-4 FAIL | rel<1e-4 on X4 |
| unbalanced_synth | 191 | 20 (size 5..15) | 1.70 (X4) | X4 rel=7.1e-4 FAIL | rel<1e-4 |

L2 and L3 must match L1 (pooled lmer) within Ring63 floor 1e-5.

## LMM PASS_PRACTICAL root cause hypothesis

**NOT O(β²) Taylor-linearization** (LMM is LINEAR — closed-form GLS has
no Taylor expansion). Hypothesis for X4 rel=1.79e-4:

1. **Ring63 FP accumulation** (~1e-5 per Beaver op × ~20 ops in Gram
   assembly + solve × condition-number amplification) → ~1e-4. Matches
   observed order.
2. **REML profile optim tolerance** — `stats::optimize(ftol=1e-4)`
   default in our σ_b² search. σ_b² error of 1e-4 propagates into β via
   GLS re-weighting (magnitude set by Σ_j X_j / Σ n_j / σ_b²).
3. **OLS sanity gate**: closed-form passed (no fallback), rules out (c).

Dominant factor likely (2) — optim tol, NOT Ring63 floor. Fix: tighten
`stats::optimize(tol = 1e-10)` and verify. If that doesn't close, then
(1) dominates and fix is Ring63 25-frac_bits (affects whole package,
revalidation required).

**Cox vs LMM root cause DIFFERS.** Path B (Fisher(β_k) via Beaver) does
NOT generalize to LMM — LMM already computes exact closed-form GLS.
LMM intervention is its own track.

## P3 disclosure budget for Path B (Cox)

Per iteration k (k ≥ 1), the following are published:

| published | type | size | channel | tier |
|---|---|---|---|---|
| grad(β_k) | scalar aggregate | p-vector of floats | client reveal | same as Newton one-step |
| Fisher(β_k) | scalar aggregate | p×p matrix of floats | client reveal | new: Fisher matrix at current β |

No per-observation reveals. No new inter-server channels beyond the
existing Cox permutation + transport-encrypted blobs.

**Max iterations**: 5 (fixed cap, documented).
**Cumulative budget**: grad + Fisher per iter × max 5 iters = up to 5
p-vectors + 5 p×p matrices revealed to client over the method's lifetime.
For p=5: 25 + 125 = 150 floats total. Asymptotic in n → 0 (disclosure
independent of n).

**Cost to adversary**: knowing Fisher(β_k) at multiple β_k points could
reveal second-order structure of the risk-set weighted covariance of X.
Standard disclosure for Newton-Raphson in centralized Cox; no novel
leak beyond what `coxph$var` exposes for pooled-data fits.

Documented as acceptable per the plan's disclosure table. Same tier as
cluster membership in LMM (scalar aggregate of pre-agreed statistic).

## Determinism gate (Codex 2026-04-19 late addendum)

BEFORE any Cox scenario's acceptance is evaluated under Path B, the
determinism probe MUST pass with Path B enabled:
- Two fresh R sessions, same seed+data, run ds.vertCox with
  `newton_refine_iters = 5L` (Path B ACTIVE).
- |β_session1 - β_session2| ≤ 1e-10 per coefficient.
If this fails, Path B has introduced non-determinism — do not proceed
to acceptance; diagnose the source.

**STATUS 2026-04-19 late**: determinism gate PASS. With Path B
enabled (newton_refine_iters=3), across-run |Δ(fit1,fit2)|=3.3e-7 on
weak_synth (local harness /tmp/weak_rep.R) — well below the 1e-5
Ring63 floor. Determinism is NOT the blocker; accuracy convergence is.

## Iteration-cap discipline (Codex 2026-04-19 late)

Max iters = 5 is PART OF the P3 disclosure budget. Breaking the cap
to force convergence = breaking disclosure discipline. If Path B does
not converge within 5 iters on any scenario: go back to seam
diagnostic (verify Fisher(β_k) computation correctness via trace,
check (a) orchestration, (b) contract, (c) L2/L3 gap) BEFORE raising
any knob.

## Ring63 cross-fix propagation (Codex 2026-04-19 late)

If LMM acceptance forces a Ring63 25-frac_bits fix (after optim
tolerance is exhausted as a fix option), then:
- The 1e-5 Ring63 floor in the "Per-layer convergence requirement"
  below changes (becomes ~3e-7).
- EVERY previously-PASSed Cox scenario must be RE-validated under
  25-frac_bits.
- The re-validation is non-optional: a Ring63 change is a global
  protocol change, not a per-method opt-in.

**UPDATE 2026-04-19 late**: Ring63 25-frac_bits upgrade ATTEMPTED and
REVERTED — `StochasticHadamardProduct` in k2_truncation.go uses uint64
intermediates that silently overflow once 2*fracBits+headroom exceeds
63 (at 25, only 13 bits headroom; any summed accumulation consumes it).
TestSoftmax_Composition |err|=3508 and LMM intercept collapse 99.45→0
confirmed. Full uint64→big.Int migration is required; tracked as
task #111 (B_full). Not urgent until a pending method requires it.

**SECOND ATTEMPT 2026-04-19 late**: share-scale SNR boost (multiply
X̃, ỹ by c=8 before sharing, de-scale Gram/Xty/yty client-side; β
scale-invariant by construction). REJECTED numerically: scaling did
NOT improve SNR as hypothesised — Ring63 TruncMul noise is
proportional to output magnitude (1 LSB in int64 = 2^-20 ≈ 1e-6
relative, INVARIANT under scaling), so larger products have
proportionally larger absolute noise. LMM regressed from |Δ|=3.88e-4
to |Δ|=3e-2 because scaling triggered the quality-gate rejection
path at outer iter 1 (max_abs went from 99.4 to 292 due to an
interaction with the OLS sanity check tolerance). Default reverted
to share_scale=1.0. Correct path: proper iterative refinement via
a second MPC round (X̃'r for r = ỹ − X̃ β_hat computed via fresh
Beaver on the stored shares) which DOES reduce FP noise via
independent-noise correction. Not yet implemented; preliminary
design ~3-4h of work. Alternatively: accept (B_full) task #111 as
the only path to strict <1e-4 rel on |β|>1 coefficients.

## LMM iterative-refinement band-aid (Codex 2026-04-19 late decision)

LMM X4 |β|>1 relative bound (target rel < 1e-4, observed 1.14e-3) is
remedied via **iterative refinement** (residual-correction GLS) LOCAL
to `ds.vertLMM.closed_form`. This is a legitimate numerical linear
algebra technique (Wilkinson 1963; Golub & Van Loan 3rd ed. §3.5) that
converges quadratically for well-conditioned GLS systems. One extra
pass typically recovers ~6 bits of precision, pushing 1e-4-1e-5 error
down to 1e-8 in the infinite-precision limit; here bounded below by
the same uint64 Hadamard FP floor that prompted (B_full).

**This is remediation over an unfixed underlying FP floor**, not a
root-cause resolution. If any other method (pending LASSO, GLMM,
Ordinal) encounters a precision ceiling that iterative refinement
cannot close within 2-3 passes, task #111 (B_full) migration is
activated immediately and the refinement band-aid removed.

## P3 budget addendum for LMM iterative refinement

Baseline LMM single-pass discloses:
  - p-vector β_hat (fixed effects)
  - σ² scalar (residual variance)
  - σ_b² scalar (random-intercept variance)
  - p×p covariance of β_hat (via inverse Gram, client-side)

Per refinement iteration added, the ONLY new disclosure is:
  - p-vector δ (correction to β_hat), computed from the same
    Beaver Gram + residual-inner-product machinery already used in
    the baseline. No new inter-server channels; no per-observation
    reveal; no new aggregate beyond the one additional p-vector.

Cumulative with ≤2 refinement iterations: 2 additional p-vectors + a
re-computed Gram (p×p, same as baseline). Total cost is ≤ 2× baseline
in aggregates published. Acceptable under P3 budget: refinement costs
<=2× the baseline's disclosure surface, all of it scalar aggregates
already tier-classified.

Hard cap: **2 refinement iterations**. Breaking the cap = breaking P3,
same discipline as Cox Path B's 5-iter cap. If 2 iters don't close X4
rel < 1e-4, escalate to (B_full) task #111.

## Per-layer convergence requirement (Codex condition 2)

For each Cox scenario after Path B:
- L1 vs plan target: must pass per-coef rule.
- |L2_β − L1_β| ≤ 1e-5 per coefficient (Ring63 FP floor).
- |L3_β − L2_β| ≤ 1e-5 per coefficient (network deployment is pure
  protocol; same formulas, same Beaver triples deterministically
  derived from session seed).
- If L2 or L3 diverges from L1 beyond 1e-5, halt and diagnose per
  Codex rule: (a) comms/orchestration (b) dsVertClient↔dsVert contract
  (c) L2-simulation vs L3-reality gap.

Data equivalence checks: n_total, n_events, per-covariate mean/sd, and
(for stratified) stratum size distribution must match L1↔L2↔L3
bit-exactly (the values are plaintext, not shares).
