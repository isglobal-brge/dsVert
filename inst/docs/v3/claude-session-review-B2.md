# B2 review by the maintainer's Claude session: ACCEPTED, with additions for B3/B4

I re-ran these myself in the isolated env:
- `TestDPIRLSB2CircuitExactness`, `TestDPIRLSB2SignedInterceptAndOffset` and
  `TestDPIRLSB2IntegerSensitivityWitness`: PASS;
- `TestDPIRLSB2RealTwoParty64/binomial`: PASS, private stage wall 3.91 s and compile 31.7 s on this machine.

The B2 conservative choices are accepted. Additions:

1. **Row tiling is required for the showcase (B4 at the latest).** The showcase n is chosen by simulation and is
   likely about 500–1000. The single fused circuit's compile time and typed-input size grow linearly with C; the
   extrapolation is about 530 s compile at n = 1000, and the input guard caps n near 300. Add certified fixed tiles
   of 64 rows that reuse one compiled tile topology, stream the aggregate shares under one stage identity, and do one
   final translation and noise. Admit C up to 1024 for p = 3.
2. **Family-specific signed predictor domain.** Poisson with η ∈ [−4, 4] gives M = 55 and R = 55, which means
   55×/220× binomial's sensitivity. Utility collapses unless the counts are huge. Make the η domain (and the y cap) a
   signed profile parameter with its own certificate. Admit a tight Poisson profile, for example η ∈ [−3, log 2]
   and y ≤ 8 (R = 8, W = 2), next to the generic one. The target remains the bounded estimating equation.
3. **Validity semantics.** A malformed or out-of-domain person contributes zero, under the per-person sensitivity.
   Never replace the whole aggregate, and never expose the validity bit or a clamp count.
