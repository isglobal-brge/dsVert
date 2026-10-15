# Phase A design review: dsVert v3 fixed-path DP Newton/IRLS

**Verdict: CHANGES REQUIRED.**

The architecture is sound. The five blockers below are specification gaps, not redesigns. Each can be closed by editing the document, without code or measurements. Once they are closed I expect to approve without reopening the agreed decisions. This review covers the draft and audit notes as given. Nothing here authorizes implementation.

## Agreed decisions (not reopened)

- **Lifecycle:** Production cross-grid lifecycle with a fused score/H GC producer. Arithmetic-product hybrid only as a later optimization with no silent fallback. Formal-GC components borrowed, not its lifecycle.
- **Noise:** Forced v4 two-full-draw convolution for every stage, under a new v3 policy, so the 51-coordinate one-draw grid policy cannot leak in. Charge ε_t once under non-collusion. No Gaussian or one-draw substitution without a new signed contract.
- **Signed coordinates:** Public translation `A_j` from padded capacity C, released in `[0,2A_j]`, subtracted publicly. A finalizer endpoint hit triggers refusal.
- **Sensitivity algebra:**
  - V1 and V2 are the exact maxima of the vech L1 and squared L2 norms.
  - Off-diagonals are counted once.
  - Rounding slack is per person, multiplied by m for per-row rounding and doubled for floor rounding.
  - Coordinate Laplace is never calibrated from L2.
  - Binomial R=1, W=1/4. Poisson R=max(M, Y−m), W=M, with the offset inside eta.
  - Tier-2/3 envelopes (NB2 dispersion, multinomial √2·B and B², PEM B(1+Mτ), GEE meat √q·G²) check out.
- **Path integrity:**
  - Each authority recomputes the successor and signs identical canonical bytes.
  - Each authority durably claims one successor per (root, t).
  - `K_t` is keyed on the predecessor's public DP payload.
  - Crash recovery never redraws noise.
  - Frozen #25 epoch vector, with no mid-path splice and no refunds.
- **Path update:** Exact rational diagonal-shift update instead of spectral flooring, recorded as a distinct estimator version that needs its own replay qualification.
- **Inference:** A budgeted terminal audit fixes the β_T off-by-one. Replay plus H⁻¹ is a **candidate only**, not statistically validated. Exact independence decomposition is rejected. Refusal uses only public or DP-derived inputs. Poisson top-coding requires a model-error certificate or a relabelled target.
- **Front door:** `ds.vertDPIRLS(analysis_id, …)` with no statistical knobs, and an offline validator that separates integrity from trust-root authenticity.
- **Validation:** Mechanism-level only, no per-family tables. Tier 3 deferred, with LMM as a stretch.

## Blockers

**1. Split-block stage atomicity is asserted but not specified.**

The draft says "authenticated vector subcalls and atomic publication of both blocks," but the reused Synopsis adapter has a single `final_noise` lane. The document must define the following:

- **(a) Lane identity.** Define `K_{t,g}` and `K_{t,H}` as domain-separated children of `K_t`, each with its own v4 plan.
- **(b) One protected evaluation.** One committed protected output per stage is partitioned into lanes. Two independent protected evaluations must not feed the lanes, unless the document proves they are bit-identical under the frozen snapshot.
- **(c) Commit rule.** The stage COMMIT and its publication record exist only after both lanes' noised final shares are durable at both authorities. No API or replay path returns a single lane. A crash between lanes resumes the missing lane under its own sticky key and never re-executes the committed lane.
- **(d) Next-stage key input.** `K_{t+1}` hashes the canonical concatenation of both lane payloads in signed order.
- **(e) Score-only stages.** These have a single g lane, with ε_H=0 represented as a signed reference to the reused H digest, not as an empty lane.
- **(f) Terminal audit.** The audit stage carries its own purpose tag in `K_T` and cannot be confused with an optimizer stage.
- **(g) Per-lane sensitivity.** §7 currently gives only joint bounds. Write per-lane integer S1:
  - `S1_g = ceil(a·(m·R·B1/s_g/h_g + p/2))`
  - `S1_H = ceil(a·(m·W·V1/s_H/h_H + q/2))`
  - Each lane has its own α = ε_lane/S1_lane and its own A_j.
  - State that the joint and split calibrations are never mixed.

**2. Validation cannot currently detect a mis-calibrated lane.**

Every listed case would pass if, for example, the H lane were noised with α computed from the joint S1 or from ε_t. Add three mechanism cases:

- **(a) Offline sensitivity witness.** On the actual integer DAG, including clamps, link approximation, person aggregation, rounding and translation, construct adversarial neighbour pairs at the envelope corners (all |x_j|=b_j, residual and weight extremes, m rows). Assert that the realized pre-noise integer L1 difference is at most S1 per lane.
- **(b) Noise-law check.** Run a noise-only synthetic fixture per lane. Compare the empirical released noise against the declared two-draw discrete Laplace at that lane's α, using a goodness-of-fit test with fixed size and power.
- **(c) Signed translation round trip.** Test negative and off-diagonal coordinates, values at ±C·c_j, and forced finalizer endpoint hits. The test must show they produce refusal and never silent zeroing.

The current "endpoint clamps" case is ambiguous between input clamps and the finalizer clamp, so name both.

**3. The rational path needs an independent verifier and a declared size bound.**

"Implemented once in Go" conflicts with the client and offline validator "recomputing the whole path."

- **Implementations.** State that the server Go code is authoritative. The client validator should be an independent bignum implementation (e.g. R `gmp::bigq`) sharing the cross-platform known-answer fixtures, not a call into the same binary. Otherwise "client validates" only re-runs the same bug.
- **Algorithm.** Specify fraction-free elimination (Bareiss) or an equivalent with a proven bit-length bound in terms of the lattice widths and d.
- **Resource ceiling.** The fail-closed ceiling must be a signed contract constant derived from that bound. It must not be chosen adaptively.
- **Shift search.** The exponential-bracket search for k needs a signed maximum k. Exceeding it is a hard path failure, not an algorithm switch.

**4. The cost gate is under-specified, and there is no early go/no-go.**

- **Fix the demo profile.** The ≤15-minute Tier-1 live gate must sign T, the refresh mask, the terminal-audit flag and the ε split for n=64, p=3. Without them, "complete short path" has no definition and the per-stage budget (15 min/(T+1)) cannot be checked.
- **State what the 15 minutes includes.** Say whether it covers cold compile, source materialization and PSI/alignment, or whether prebuilt hashed artifacts are allowed with cold costs reported separately. I recommend prebuilt artifacts allowed and cold costs reported. The exported `ds.vertGLM` n=2000 grid=2 runs (46–63 min) show that DSI and materialization, not products, can dominate.
- **Add an early measurement milestone.** At the end of Phase B week 2, measure one fused p=3, n=64 stage end-to-end through R/DSI before the client and inference work proceeds. If it exceeds the per-stage budget, the documented outcome is to redirect to the arithmetic-product optimization or accept a performance-gate failure. Do not discover this in week 4.

**5. The eight-week scope is internally inconsistent.**

- **Phase D conflicts with the plan.** The milestone table places Phase D in week 8 and §10 lists a Tier-3 demo command. Meanwhile B+C already total 30–42 engineer-days of about 40 available. Remove Tier 3 from the eight-week plan entirely (it starts only after Tier 2's first slice passes) and mark the Tier-3 demo command conditional.
- **The inference estimate is too small.** "3–4d for the mechanism/inference gate and live demo" cannot include threshold freezing via a whole-mechanism coverage campaign. State that within eight weeks Tier 1 ships with inference status *candidate/unavailable*. The 3–4 days covers refusal-semantics correctness, replay determinism and the live demo. Qualification is a separate, uncommitted campaign.
- **Answer the open question.** Yes, cut Tier 2 before attempting any Tier 3. Order Tier 2 as person-period/PEM (which reuses Tier-1 producers), then multinomial. NB2 and ordinal are explicitly post-week-8 unless slack is demonstrated.

## Non-blocking recommendations

- **N1. Refusal scope.** Refusing on any intermediate shift or trust truncation will likely refuse nearly every every-stage-H fit at small n. That would leave the candidate with no accepted fits for Phase B to study. Shifts, truncations and interior projections do not move the fixed point, and the replay already includes them. Consider refusing only on terminal-stage shift, truncation or projection, on final-iterate box contact, and via the optimization-radius certificate, while still reporting intermediate events. Either choice is acceptable if signed before data access.
- **N2. Terminal audit SE.** H_T is noisy. The qualification study should check SE calibration from `H̃_T⁻¹` itself, not only coverage of the point estimate.
- **N3. Replay seed.** Bind the replay-seed derivation and replicate count into the inference profile hash, as the audit notes say. The draft implies this but should state it in §8.
- **N4. Open choices.**
  - Signed translation: accepted.
  - Split-block publication: accepted, subject to blocker 1.
  - Terminal-audit privacy trade-off: accepted. Estimate-only contracts may omit the audit and cannot add it later.
  - Rational shift semantics: accepted, subject to blocker 3.
  - Provisional thresholds: acceptable as provisional and signed, with the "not a coverage proof" language kept.

## Status

The verdict is **CHANGES REQUIRED** with blockers 1–5. When a revised document addresses them, I will review only those deltas against a fixed document hash. If they are closed as described, I expect to approve the design for future Phase B. No code exists or is authorized by this review, and the inference route remains a guarded candidate, not statistically validated.
