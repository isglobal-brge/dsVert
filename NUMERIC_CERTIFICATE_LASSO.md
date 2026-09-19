# LASSO public-penalty numeric extension

Let S=2^g, public capacity N and public candidate beta_j,lambda_j. The base
binomial/Poisson row loss and its clamp must be the certified piecewise-
polynomial implementation approved by DECISION_DAY1_ARITHMETIC_ROUTE.md.
This extension inherits that producer's signed U_j, coordinate maxima, Delta_1
and Delta_2 unchanged. The historical NUMERIC_CERTIFICATE_V1.md remains an ABI
reference; its q64 transcendental approximation is not the production route. The public penalty is

`P_j = ceil(N*S*lambda_j*sum_{k>0}|beta_jk|)`.

The implementation computes this rational expression exactly for the signed
binary64 candidates, including subnormal coefficients. IEEE binary64 decoding
produces a nonnegative integer mantissa and an integral power-of-two exponent.
Base-2^15 limb multiplication and carry normalization are exact in R binary64:
a mantissa uses four limbs, capacity three, and each multiplication accumulator
contains fewer than eight products below 2^30. Shift/add operations produce at
most 150 limbs over the public domain. Integer quotient/remainder division by a
power of two is exact. Conversion to an R integer-valued double occurs only at
the final nonnegative quotient, which is rejected above 2^53-1. The final ceiling
adds one iff an exact nonzero remainder exists. No protected values enter this
calculation and no MPC multiplication or GC gate is necessary.

Against the real public penalty evaluated on those signed values,

`0 <= P_j/(N*S) - lambda_j*||beta_j,slopes||_1 < 1/(N*S)`.

This is deterministic public quantization, not statistical or privacy noise.
It adds zero privacy sensitivity. Floating evaluation of the final public score
adds ordinary binary64 postprocessing rounding; this does not affect DP and is
not claimed to preserve arbitrarily close real-valued ties. Canonical ties in
the implemented public score choose the first signed candidate.

For binomial/Poisson, let E_j be the certified producer's full per-valid-row
absolute loss error, including profile interpolation, coefficient quantization,
shared-predictor rounding and final release-lattice rounding. If its certificate
states only pre-output error e_pw, include 1/(2S) in E_j. Since valid rows <= N,
capacity-normalized summed loss error is <= E_j. Including the public penalty
makes the total error < E_j + 1/(N*S), before DP noise and final binary64 score
rounding. For a per-lambda selected candidate, approximation alone adds at most
twice the largest candidate error to its exact finite-grid objective gap.

The new producer must sign profile tables, rounding and certificate identity,
prove U_j/S encloses its implemented row loss plus the certified profile error,
and check dense-domain errors and n*E_j well below its actual DP noise scale for
certified defaults. This public penalty cannot inherit a numerical bound from
an unavailable or rejected kernel. The LASSO registration records the required
arithmetic route but does not claim that its production producer is wired.
Frozen Step-1 contract fixtures test only authentication and public algebra.

For adjacent datasets D,D', P_j is unchanged, hence
`(Lhat_j(D)+P_j)-(Lhat_j(D')+P_j)=Lhat_j(D)-Lhat_j(D')`.
Thus unique base release caps remain U_j and its joint sensitivities remain
`Delta_1=a*sum_j(U_j)`, `Delta_2=a*sqrt(sum_j(U_j^2))`, with the producer's
outward numerical guard. Coordinate maxima before noise remain N*U_j; the
public score offset is applied after authenticated joint DP noise and never
used as a secret-coordinate cap. Reusing an already released coordinate for
several public lambda values adds no release or sensitivity. In particular,
these formulas are for the unique base vector, not an unnoised duplicated
candidate vector.

For Gaussian, use the existing signed sufficient-statistic numeric certificate;
no nonlinear profile or new MPC loss is introduced. Every released moment has per-sum absolute lattice error at
most N*e, e=2+1/(4S). Evaluating half RSS at a public candidate gives the
conservative normalized error bound

`e/(2S) * (||beta_j||_1^2 + 2||beta_j||_1 + 1)`.

The squared L1 term bounds the quadratic-form error, the linear term bounds
XTy, and the final one bounds yty. Add <1/(N*S) for penalty quantization.
This statement excludes DP noise and final binary64 arithmetic. It neither
changes moment caps nor converts the existing Gaussian moment release into a
candidate-loss workload. Public-capacity normalization uses no noisy count.
