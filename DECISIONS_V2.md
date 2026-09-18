# Step 2 decisions

## 2026-09-18T12:45Z — resumed

1. Preserve the committed V1 profile, references and signatures. The arithmetic
   addendum supersedes its nonlinear arithmetic, not its source f50 encoding,
   ownership, alignment, complete-case semantics or release authorization.
   A replacement profile requires its own identity, hash and error certificate;
   old signed q64 contracts must never silently select new arithmetic.
2. Measure a new Boolean-engine piecewise profile before integrating release.
   The existing ring/spline implementation is not a drop-in certified backend:
   its binomial/Poisson domains are hardcoded, its tail rules differ, and its
   coefficient generation uses ordinary floating point. Its trusted combined
   preprocessing helpers do not establish two-authority production security.
   No sealed generation-one route will be reopened.
3. Preserve all baseline files. Newly generated numerical fixtures contain only
   public coefficients and synthetic inputs. A profile cost experiment is not
   a completed kernel, release, or whole-workload benchmark.

## 2026-09-18T13:02Z — candidate profile and measured cost

4. Evaluate quadratic interpolation at interval endpoints and midpoint, K in
   {16,32,64}, signed public envelope A in {1,2,4,8,16}. Use f16 nonlinear words
   except full-domain Poisson f6; exp(16) cannot fit a 32-bit f16 word. Retain
   exact 64-bit raw products and nearest-even rounding. This is a proposed new
   arithmetic identity, never a reinterpretation of a signed V1 contract.
5. An initial f26 binomial / larger-fraction Poisson probe was too costly.
   Regenerate the certificate for the lower precision before measuring it.
   Keep the final reproducible variants, not obsolete coefficient files.
6. The compiler's default wide multiplication and unreduced constant-table
   logic overestimate the useful Boolean circuit. A test-only Boolean
   constant-folding/shared-expression pass and the existing array-multiplier
   option provide a smaller exactly equivalent circuit. Exhaustive 8-bit
   comparison and all profile boundary/random comparisons pass. No shared
   production engine code, compiler defaults or sealed family route changed.
7. Gate counts include input-share reconstruction, range handling and output
   masking in this component probe. Count a 128-bit garbled label as 16 bytes;
   exactGCGarbledRowSize returns labels, not bytes. Report actual encrypted
   protocol traffic separately from garbled-table payload and extrapolations.
8. Do not promote this candidate: the optimized K=64 circuits still exceed
   2,000 AND gates/evaluation, and full-domain Poisson utility is not certified
   relative to production noise. Batching amortizes OT/framing but cannot
   eliminate per-evaluation table payload. A new arithmetic design remains
   necessary; benchmark projections are not completed grid runs.
9. No DESCRIPTION/NEWS/roxygen changes are warranted for test-only experiments.
   No exported or internal production R function changes, no client changes,
   and no new materialized-state claim are made. The three evidence files
   explicitly distinguish completed component tests from unexecuted gates.

## 2026-09-18T13:12Z — resumed; binding revised cost gate

10. Addendum 3 supersedes decision 8's numerical cost thresholds: <=5000
    AND/evaluation and <=60 GB measured two-direction whole-release traffic.
    Retain the certified binomial candidate; do not optimize below that gate.
    Component table bytes alone do not establish the whole-release gate.
11. Replace full-domain Poisson interpolation with fixed-point range reduction
    and a short piecewise polynomial for the reduced exponential. Certify
    reduction, polynomial, rounding and power-of-two reconstruction separately.
    New arithmetic remains unadmitted until its signed identity and production
    lifecycle are implemented; never reinterpret existing signed q64 contracts.

12. Certify eta26, ln2/reciprocal f30, reduced residual f24 and quadratic
    mantissas f27, with K in {16,32,64} on [-1/2,1/2]. The shared source f50
    encoding remains fixed. Use exact uint64 multiplication temporaries;
    polynomial states fit signed32. Full-domain f16 output requires 40 bits
    and a uint64 container. Narrow the residual subtraction only after proving
    its signed30 bound. A six-stage guard/sticky barrel shifter rounds once.
13. K=64 is both the cheapest measured range-reduced candidate (3540 AND,
    versus 3546/3643 for K32/K16) and the most accurate. Select it for further
    integration. Its pre-output loss bound is 3.17234243e-5 at A4 and 1.43799821
    at A16. The R utility assertion is explicitly scoped to A4, 16 equal-cap
    candidates, n2000 and epsilon<=8; arbitrary production grids still need
    the admitted public utility/resource plan checks.
14. Add opt-in fixed-topology framing to the existing exact-GC protocol core.
    The old entry functions always select the old mode, preserving their
    context digest and every transmitted row-length word. The new mode omits
    per-gate row lengths only after both peers authenticate a domain-separated
    digest committing all gate operations/wires and input/output geometry.
    This saves ~49 KB/evaluation for Poisson without changing arithmetic,
    garbling, KOS OT, encryption or DP parameters. No production dispatcher
    selects it yet. This is the sole changed shared infrastructure; other
    family lanes can adopt it only with their own bound public plans.
15. Batch 32 nonlinear evaluations for component measurements; report total
    bidirectional encrypted bytes including fresh OT/setup. Binomial retains
    its certified K64 polynomial and uses the same uint64 masked-output test
    container for comparable framing. Its ~33 extra ANDs are container work.
    Component projection is not a measured full-size release or evidence that
    the full source/validity/loss/noise computation fits 60 GB or 30 minutes.
16. Validate pooled synthetic objectives in Layer 1 now: n2000, p6 split3/3,
    dyadic known coefficients, 16 nearby candidates plus glm's fitted vector.
    Poisson outcomes are bounded at 4 before fitting, consistent with the
    signed bounded-outcome semantics. Compare the same bounded data with
    independent R distributions and glm logLik, never label this a DSLite run.
