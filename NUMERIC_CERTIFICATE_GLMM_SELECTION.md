# Poisson GH5 coefficient-selection objective, v3

The share-composed selection profile is
`grouped-gh5-poisson-selection-shift2-q16-v3`. It accepts privately validated
live shares in ScoreShares' final operand, **not log-factorial shares**.
The signed mirrored R numeric contracts bind this profile and shift.

For each live row, use exp(t)-y*t+2 in place of exp(t)-y*t+log(y!).
For a fixed cluster the change is D=sum_live(2-log(y!)), independent of beta
and GH5 node. Thus every node log score decreases by D; centered differences,
quadrature exponentials and their sum stay identical, and the negative log
quadrature increases by D. Summing clusters preserves coefficient argmin.
No factorial approximation occurs in this selection arithmetic. The exact
integer q16 translation also holds before final quantization. Later output
rounding may change ties; the declared estimand is the signed quantized shifted
selection grid, not bitwise equality to an old quantized full-loss grid.
Likewise the DP mechanism uses the newly signed support and calibration;
there is no claim of identical noisy choices under the old mechanism.

The shift is necessary for the nonnegative terminal ABI. Without it,
exp(t)-4*t is negative near log(4), so the existing clamp would change ranking.
For y=1..4 the global minimum is y-y*log(y), smallest at y=4.
log(4)<7/5: the positive exponential series through degree five at 7/5
already exceeds 4. Hence exp(t)-y*t+2 > 2/5 for every admitted y,t;
y=0 is positive as well. The retained exp profile error (0.0055) is smaller
than this margin. Complete q16 eta/node range is within [-5/2,5/2].
exp(5/2)<13, so the shifted row loss is below 13+4*(5/2)+2=25<32.
The existing signed int32 node bounds and Ring192 accumulation remain safe.
The existing conservative GLMM cluster-error bound still covers this profile:
it includes the old factorial error allowance, now unnecessary but harmless.

Signed per-candidate caps now bound exp(t)-y*t+2 at interval endpoints and add
the existing outward error allowance. Convexity gives the endpoint maximum.
They therefore do not clip an in-domain real selection loss; per-cluster
rounding/error slack and full-vector patient sensitivity remain in force.
Private live masks must be identical across candidates and validated upstream.

The legacy monolithic compiler/reference still represents a full loss VALUE.
It retains factorials and corrects log(3!) to117425 (nearest q16), using the
same coefficient values as the independently certified v3 GEE table. It is
not the selection producer. Client `loss_objective` labels the shifted
selection value explicitly; it must not be interpreted as a full likelihood.

Verification: share-composition circuit and integer translation tests,
including y=3, wrapped Ring192 shares, both variances and missing live rows;
paired signed R contract tests. Pod results are recorded separately. No
production release, capacity admission or family promotion follows from this
arithmetic change.
