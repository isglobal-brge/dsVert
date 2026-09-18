# Numeric certificate V1 — cross-owner finite grids

Status: contract and cleartext integer reference only; no production kernel or release route.

| Profile | Input / coefficient f | Nonlinear q | Output g | Predictors p | Certified pre-rounding loss error | Strictest target | Signed arithmetic |
| --- | --- | --- | --- | --- | --- | --- | --- |
| softplus Chebyshev degree 256 | 50 | 64 | 8–18 | 1–16 | <3.242e-8 | 2^-20 = 9.5367431640625e-7 | 192 bits |
| quarter-exp Chebyshev degree 32, two squares; log-factorial 0–1024 | 50 | 64 | 8–18 | 1–16 | <1.342e-7 | 2^-20 = 9.5367431640625e-7 | 192 bits |

Common profile identity: `cross-grid-chebyshev-q64-softplus256-exp32-v1`.
Profile SHA256: `748900bb7f0d4d1026ba5e9b162bfb16e45e306033851dfc203c2461a6a78e4f`.
Certificate SHA256: `887fdf3eb38528bde7497580ba90b13d187bee94da54d67fd2c55e813565e1d8`.
Hashes use recursively key-sorted compact JSON. The pinned profile covers all polynomial and log-factorial integers and evaluation order. The certificate covers error and width bounds. R additionally pins each complete family numeric-template hash.

The machine-readable report is `NUMERIC_CERTIFICATE_V1.json`; all exact constants and shared batch fixtures are in `inst/cross-grid-v1/numeric_profile_v1.json`. The decimal bounds in the table are the authoritative outward bounds; longer decimal evaluations below are explanatory values.

Reproduce the interval calculation and byte-check its artifact with Python 3 and mpmath 1.3.0:

```sh
python3 inst/cross-grid-v1/generate_numeric_profile_v1.py inst/cross-grid-v1/numeric_profile_v1.json --check
```

The generator checks interval coefficient endpoints and exact rational upper-bound inequalities. Go separately compares the integer evaluator with 256-bit transcendental references, including endpoints and encoded-range slack. These pointwise tests supplement the uniform proof.

## Frozen integer semantics

The frozen profile uses f=50 for normalized features and public coefficients,
q=64 for nonlinear arithmetic, and signed 192-bit intermediate arithmetic.
Coefficients and q64 constants are signed decimal integer strings. Only the
feature integers (0 through 2^50), integer outcomes and bit validities enter
the existing R-exact source transport. Beta=8 encodes as 2^53 and is therefore
never transported or parsed as an R exact-integer coordinate.

Every rounding operation is nearest, ties to even, symmetrically for negative
values. Sum all public-beta products exactly at fraction scale 100, including
the intercept multiplied by 2^50 once; round the complete dot product to q64
once by division by 2^36. Partitioning predictors between owners cannot change
this result. Set t=round_even(eta_q64/17), interpreted at q64.

Both polynomials use Chebyshev first-kind coefficients c0..cn. Set b[n+1]=
b[n+2]=0. For k=n down to 1, set b[k]=c[k]+round_even(2*t*b[k+1]/2^64)
-b[k+2]. Return c0+round_even(t*b1/2^64)-b2. The exp core approximates exp(17t/4);
two q64 rounded squarings give exp(eta). The binomial y*eta term is a binary
outcome mux. Poisson uses bounded integer y*eta and one private selection from
the log(y!) q64 table, indexed over 0..M, per patient. The fixed-size validity
AND including private alignment then masks losses for every candidate.

Clamp q64 loss to [0, U_j*2^(64-g)], round to the output lattice by dividing
by 2^(64-g), then sum patient integers. Clamping before or after quantization
has the same integer result because U_j is integral; this ABI chooses before.

## Analytic polynomial certificate

The degree-n Chebyshev interpolant at n+1 roots has uniform error at most
4*M*rho^(-n)/(rho-1) when the function is analytic inside its Bernstein ellipse
and its complex modulus on that ellipse is bounded by M. This is an analytic
uniform bound, not a sampled grid claim. The implementation computes each
interpolant coefficient with a 90-decimal-digit outward interval DCT, rounding
the interval midpoint to q64 and checking both endpoints are within one q64
ulp of the resulting exact decimal integer. Exact mathematical coefficients
are enclosed by those intervals. Public log-factorial entries are similarly
enclosed by outward interval sums of log(k), with error below one q64 ulp.

To see the uniform bound directly, analytic Chebyshev coefficients satisfy
|c_k|<=2M rho^-k by their contour integral. At Chebyshev roots, each T_k with
k>n aliases to a signed T_l with l<=n, or zero. Thus
||T_k-I_n T_k||_infinity<=2. Summing the geometric coefficient tail gives
4M rho^-n/(rho-1).

For softplus(17t), n=256, rho=11/10, M=32. On the ellipse |Re z|<17.1 and
|Im z|<1.7 for z=17t. Write softplus(z)=z/2+log(2*cosh(z/2)). Since
|Im z/2|<0.85<pi/2, cosh(z/2) has positive real part, so this branch is analytic.
Also |2*cosh(z/2)|>=2*cos(0.85)>1 and |2*cosh(z/2)|<=2*exp(17.1/2).
Thus its logarithm has modulus <17.1/2+log(2)+pi/2. Also |z/2|<9,
so the total modulus is <9+8.55+log(2)+pi/2<20<32. The resulting uniform interpolation error is
3.2410264038845832728e-8.

For exp(17t/4), n=32, rho=4, M=10000. Its maximum real exponent on this ellipse
is (17/4)*(4+1/4)/2=289/32=9.03125; exp(289/32)<10000. The entire function is
analytic there, and the interpolation bound is 7.2280144832366962267e-16.

## Integer evaluator and loss error

Let u=2^-64. Coefficient quantization contributes at most (n+1)*u because
|T_k(t)|<=1. Each rounded Clenshaw product contributes at most u/2, and its
effect is exactly an additive perturbation of a Chebyshev coefficient. The
combined contribution is at most 1.5*(n+1)*u. Argument rounding contributes
at most n^2*||P||_infinity*u/2 by Markov's polynomial inequality. Polynomial
norm bounds 18 (softplus) and 71 (quarter exp) include their analytic errors.
The complete encoded eta range and its rounded t lie strictly inside [-17,17]
and [-1,1], respectively, so no extrapolation is used.

Therefore E_soft_eval <=256^2*18*u/2+1.5*257*u=3.1995321106079166e-14 and
E_exp_core_eval <=32^2*71*u/2+1.5*33*u=1.9733292690865545e-15.
For each rounded square propagate error by E'<=2*B*E+E^2+u/2, first B=71,
then B=71^2. This yields E_exp_total<=3.859899638096306e-9 over the entire
profile domain, including argument/coefficients/evaluation and both squarings.

For ex=ebeta=2^-51, p<=16 and sum|beta|<=16, the error between the original
real eta and the encoded q64 eta is bounded by
E_eta <=16*ex+17*ebeta+16*ex*ebeta+u/2
       =1.4654971030106382e-14.
The 17 coefficient terms include intercept. This is deliberately conservative
because the first term need only sum slope magnitudes.

The binomial loss derivative in eta has absolute value <=1 for either binary
outcome. Its total pre-output-rounding error is E_eta+E_soft_poly+E_soft_eval,
less than 3.242e-8. Poisson loss derivative is bounded by exp(16+E_eta)+1024;
including the q64 log-factorial table error gives total less than 1.342e-7.
Both are strictly below 1/(4*2^18)=9.5367431640625e-7, hence also meet all
g in 8..18. Clamping both the integer approximation and the real-valued target to the
signed interval [0,U_j/S] is nonexpansive. Output ties-even rounding adds at
most 1/(2S), giving a per-patient natural-unit error of at most 3/(4S)
against that bounded target. The same statement against the unclamped real
loss additionally requires U_j/S to enclose it. The inherited binary64 public
loss-bound formula is not a new interval proof of transcendental cap rounding;
the exact integer clamp guarantees sensitivity independently of that issue.

## Width certificate

Strict absolute bounds recorded as powers of two include rounding slack:

| Operation | Bound on absolute encoded integer |
| --- | --- |
| Source feature f50 | <2^51 |
| Public beta f50 | <2^54 |
| Complete exact dot f100 | <2^105 |
| Eta q64 | <2^69 |
| Clenshaw state q64 | <2^89 |
| Clenshaw raw product | <2^155 |
| Either exponential square raw product | <2^155 |
| Assembled loss q64 | <2^90 |

To derive the largest Clenshaw bound, every Chebyshev coefficient has modulus
at most 2M plus one q64 ulp. A Clenshaw state is a sum of coefficients times
Chebyshev polynomials of the second kind; |U_k(t)|<=k+1 for |t|<=1. Thus state
modulus is at most (2M+u)*(n+1)*(n+2)/2 plus rounding, below 2^25 for either
profile. Multiplication by |2t|<=2 and the q64 scaling gives a raw product
below 2^155. The first exp result is <71, its first square <5042, and the
second raw square is <5042^2*2^128<2^153; 2^155 is conservative. Full exp/loss
below 2^26 covers exp17, integer outcome*eta, log(1024!), and rounding.

All raw integers fit a signed 192-bit representation with at least 36 bits of
sign-safe headroom at the largest allowed bound. Output candidate caps,
capacity*caps, and workload sensitivities must separately pass <=2^53-1
checks in the R signed-contract builder. The signed source Ring128 layout is
only an input/share transport representation, not the width of polynomial
products in the future fused circuit.

## Sensitivity and representability

For candidate j, A_j=sum_k |beta_jk|. Use the existing public formulas:

- Binomial L_j=softplus(A_j).
- Poisson L_j=max_{y in 0..M, eta in {-A_j,+A_j}} [exp(eta)-y*eta+log(y!)]. Convexity in eta makes the endpoints sufficient.
- U_j=ceil(2^g L_j); coordinate maximum=N U_j.
- Delta_1=a sum_j U_j; Delta_2=a sqrt(sum_j U_j^2), with a=1 for add/remove and a=2 for fixed-cohort replacement.
- Natural-unit sensitivities are the integer sensitivities divided by 2^g. The implementation uses the existing server's outward L2 floating-point guard, sqrt(sum)*[1+32 epsilon], so it conservatively encloses the displayed formula.

All caps, coordinate maxima, and workload sensitivities must be finite and at most 2^53-1; dimensions and capacity are also bounded before layout construction. At A=16, g=18 and M<=1024, the worst Poisson public cap is 2,329,440,556,289, allowing N<=3,866 from the coordinate constraint alone. Multiple candidates may impose further workload limits. The complete private transport layout is capped at 64*1024^2 coordinates.

Source encoding error is measured against the bounded, normalized feature values supplied to the new encoding boundary. Any future preprocessing implementation must preserve this definition or account for additional normalization error. No independent owner partial dot-product rounding is permitted.

`test-dp-capsule-materializer.R` compares the new sensitivity helper with the actual existing server workload builder for both families and both adjacency modes. The client tests compare with `.dsvert_dp_glm_grid_loss_bounds` at g=8,16,18 including the largest coefficient domain. Fixtures with deliberately smaller artificial caps test saturation only; signed model caps always come from the derived public formulas.
