# Multinomial certified piecewise fixed-point certificate

## Active arithmetic route (2026-09-18 reviewer addendum)

Active profile: `cross-grid-multinomial-piecewise-q16-v1`. This supersedes
protected-row use of the q64 profile in the historical appendix. Frozen f50
source encoding, exact f100 owner partial predictors, signed classes, private
validity and integer output quantization remain unchanged. Protected nonlinear
kernels use exactly evaluated public piecewise quadratics with 32-bit q16 words.

The shared document `inst/cross-grid-family-b/piecewise_profile_v1.json` binds
SHA256 `fc0d85381d6effb30776848ccf301f4b9b18fc5dc55bdc80a8503f7d8916fcef`
of its canonical sorted-key compact-JSON `profile` member. The separate
`piecewise_certificate_v1.json` binds the deterministic analytic bound payload
with certificate SHA256
`b480edd4ab1ad8f2403026f2d718bfd093068816160a893ee0f7935056251f67`.
The generator uses
Decimal precision 90. Correctly rounded Decimal exp/ln and elementary
operation rounding contribute less than 1e-70 coefficient error after scaling.
Minimum scaled distances from a rounding tie exceed 0.01188 (exp), 0.000725
(log), and 0.004517 (softminus); all pinned integer roundings are unambiguous.

## Domain and exact profile semantics

Retain 2–8 classes, p<=16 normalized predictors, at most 256 candidates,
coefficient component magnitude <=8 and class-block L1<=16. Reference eta is
zero. Add complete f100 partial predictors before rounding directly to q16 by
2^84, nearest ties even. Intermediate q64 rounding is forbidden because it can
change q16 halfway results. The existing nine-f50-unit encoding slack remains
in the private domain guard and rounds to the q16 endpoint 16.

Subtract the maximum over reference and nonreference scores. Exponential inputs
are in [-32,0]. The exp table uses 64 pieces of width 1/4 on [-16,0]; inputs
below -16 return zero. At zero, exp explicitly returns 65536. This exact branch
ensures a sum >=1; the uncorrected endpoint polynomial would return 65535.
The sum is <=8. Normalize for log to a q16 mantissa in [1,2], exponent 0..3;
the log table has 64 pieces of width 1/64 and q16 log(2)=45426. Evaluate

    maximum + log_profile(sum(exp_profile(eta_k-maximum))) - eta_y.

For each table, let t=x-left. Store the endpoint/midpoint interpolation
coefficients `[c,b,a]` rounded to q16 and evaluate

    c + round_even(t * (b + round_even(a*t/65536)) / 65536).

Each kernel has two multiplications. Width is proved for every input, not by
sampling: for each signed coefficient triple and integer 0<=t<=step, bound
first product by |a|step, second by (|b|+ceil(|a|step/Q))step, and result by
|c|+ceil(second/Q), Q=65536. The maxima (first,second,result) are respectively
(474398720,950042624,65536) for exp, (33037312,67622912,45431) for log, and
(133611520,570212352,54127) for softminus. All are below 2^31. The checker
asserts these universal tablewise interval bounds separately from regression.
Ring192 remains for the frozen ABI, masks, exact f100 reconstruction and loss
transport. The complete row invokes several kernels according to class count.
This numerical certificate makes no claim that the Boolean row meets the
reviewer's 2000-AND target; measured gate/traffic and arithmetic-share producer
integration are separate gates.

## Analytic error

Let u=2^-16 and h be the piece width. The quadratic interpolation remainder is
at most `sup|f'''| h^3/(72 sqrt(3))`. Coefficient and Horner-product rounding
contribute at most `R(h)=(u/2)(2+2h+h^2)`.

For exp, sup|f'''|<=1 and sqrt(3)>17/10 give
`E_exp<=47233/320864256<0.000147206`. The truncated tail exp(-16)<2^-23 is
smaller than this bound; the exp(0) branch is exact. For log on [1,2],
sup|f'''|<=2. Normalization adds at most u/(2-u), and exponent-times-log(2)
adds at most 3u/2. Consequently
`E_log<=496102395623/10766335717933056<0.000046080`.

At least one maximum exponential is exactly 1, leaving at most seven
approximate terms. Since the exact sum is >=1, its log perturbation is at most
`7 E_exp/(1-7 E_exp)`. The loss gradient L1 norm in the original scores is <=2,
so q16 eta rounding contributes at most u. Frozen f50 encoding is covered by
an additional 1e-12. Thus the active **prequantization error is e_pw=0.0011**.
For g>=16 output conversion is an exact shift; for g<16 add
`e_out=2^(-g-1)`. The uniform row error is <=e_pw+e_out, including slack and
halfway cases. Clamping is nonexpansive against the equally clamped real loss.

## Caps, sensitivity and utility

For candidate j put `A_j=max_k sum_l |beta_jkl|`, `L_j=2 A_j+log(K)`, and use
an outward-rounded `U_j=ceil(2^g (L_j+2 e_pw+e_out))`. This cap exceeds the
maximum quantized profile loss by at least e_pw. Clamp the contribution to
[0,U_j]. Add/remove sensitivity is Delta1=sum U_j and
Delta2=sqrt(sum U_j^2); the inherited conservative replacement convention
multiplies both by two. Coordinate maxima are N U_j. Caps, maxima and both
sensitivities remain <=2^53-1, with the inherited outward L2 guard. Privacy
follows from exact integer clamping independently of approximation error.

Utility is selection under an objective within n*(e_pw+e_out) of the exact
loss; a pairwise comparison may differ by twice that amount. The declared
certified default envelope is n=10000, m=50, g=18, K=8, and full-domain A=16.
The n*e_pw/Laplace-coordinate-scale ratios at epsilon 1,4,8 are at most
0.006456, 0.025821, 0.051641 (5.17% at epsilon 8). These are not universal
claims for smaller grids or smaller signed caps; check the actual public
envelope. No epsilon, delta, cap or sensitivity is weakened.

## Reproduce

    python3 inst/cross-grid-family-b/generate_piecewise_profile.py
    python3 inst/cross-grid-family-b/generate_integer_fixtures.py
    python3 inst/cross-grid-family-b/verify_numeric_certificate.py

The checker verifies rational inequalities and pinned regeneration, then
262404 numerical points. Observed maximum absolute errors are 1.24010e-4
(exp), 1.52345e-5 (log table), 2.68201e-5 (softminus), 2.38430e-5 (normalized
log). Dense evaluations are regression evidence, not the proof. Another
593 pinned table/kernel boundary words and eight row cases cover coefficient
slack, f100 q16-halfway plus/minus one raw unit, masks, eight classes, rare
ordinal categories and saturation. Go and pure-R integer outputs must agree.

## Historical superseded certificate

The following prior arithmetic route and protected-row error claims are
superseded. Only its PUBLIC ordinal gap-constant proof is still used.

---

# Multinomial fixed-point certificate extension

Profile: `cross-grid-multinomial-exp32-log24-q64-v1`. This extends, and does not
replace, `NUMERIC_CERTIFICATE_V1.md`. It certifies the integer loss kernel;
authentication, source preparation and joint DP release are separate gates.

## Domain and integer semantics

There are 2–8 classes, 1–16 normalized predictors in [0,1], and at most 256
candidate coefficient matrices. The reference score is zero. Each remaining
class has an intercept and slopes, component magnitude at most 8 and exact
binary64 L1 sum at most 16. The signed class order puts the reference first;
coefficients follow the signed nonreference class order, each in intercept,
then predictor order. Class labels become private zero-based integers.

Features and coefficients use f50. Each owner accumulates exact f100 partial
predictors, with the intercept included once. The circuit adds their Ring192
shares and rounds the complete sum once to q64. No partial-predictor rounding
is permitted. A conservative encoding slack of nine f50 coefficient units
admits the frozen p≤16 domain; all eta and polynomial arguments remain
strictly inside the original [-17,17] interval. The frozen degree-32
quarter-exponential and its two q64 squares are unchanged.

Compute `log(1 + sum(exp(eta_k))) - eta_y`, with observed reference score zero.
The sum is at least one and below 2^27. Every class is evaluated regardless of
the private label. Validity, class-domain and eta-domain guards are private;
out-of-domain eta is replaced by zero before nonlinear evaluation. A rejected
guard cannot authorize release. Clamp to the signed integer cap divided by
2^g, round nearest ties-even, mask invalid rows, and sum row integers.

## New logarithm proof

For positive q64 input X, set r=floor(log2(X))-64 and normalize once to
M=round_even(X/2^r), or use an exact left shift when r<0 for public ordinal
constants. Thus m=M/2^64 lies in [1,2], including a possible rounded upper
endpoint. Set z=round_even((M-Q)Q/(M+Q))/Q, Q=2^64. Evaluate

    log(m) = 2 sum_{i=0}^{23} z^(2i+1)/(2i+1) + remainder

with q64 multiplication, recurrence `term <- round_even(term*z2/Q)`,
`z2=round_even(z*z/Q)`, and ties-even division of each term by its odd integer.
Add r times the q64 constant `12786308645202655660` for log(2).

Let u=2^-64. Then |z|≤1/3+u/2 and the analytic series tail is bounded by
`2*z^49/[49*(1-z^2)] < 2^-80`. Normalization perturbs log by less than u;
division contributes at most u/2 to z. On this interval the derivative of
the series with respect to z is less than 3. The rounded z² contributes at
most u/2. If e_i bounds the recurrence error for fixed z, then
`e_(i+1) <= (1/8)*e_i + u/2 + u/2`, since z²+u/2<1/8 and |term|≤1.
Consequently e_i<2u. Twenty-four rounded divisions, their exact sum and its
factor of two contribute less than 120u. With |r|≤27, log(2) quantization
adds less than 14u. These contributions are safely below 1024u, and the
complete logarithm error is less than 2^-50, including the tail.

The reproducible rational checker also encloses log(2) independently using
100 positive atanh(1/3) terms and an analytic tail; both endpoints round to
the pinned q64 integer. No grid of sampled points is used as the proof.

## Composed error and width

The inherited exponential uniform error is less than 4e-9, and inherited eta
encoding error less than 1.4656e-14. The sum of at most seven exponentials has
error less than 28e-9. Because its real value is at least one, its log error
is at most `28e-9/(1-28e-9)`. The multinomial loss has gradient L1 norm at
most two in the nonreference predictors. Adding the log-kernel and eta
errors gives a uniform prequantization loss error **less than 3e-8**.

The largest frozen exponential raw product remains below 2^155; new log
numerators and q64 products are below 2^132, and assembled losses below
2^71. The complete f100 dot is below 2^105. All fit signed 192-bit arithmetic.
These bounds describe admissible reconstructed values, not individual
uniform ring shares. Source Ring128 records retain the frozen ABI; the
fused producer must widen and form exact f100 shares inside MPC.

Clamp both the approximation and the real target to [0,U_j/2^g]. Clamping is
nonexpansive. Since 3e-8 < 2^-20, output rounding gives total row error at
most 3/(4*2^g) for every g in 8–18. As in V1, binary64 public cap formulas
are not a new interval certificate: the stated error targets the equally
clamped real loss. Exact integer clamping proves sensitivity independently.

## Sensitivity

Let A_j=max_k sum_l |beta_jkl|. All scores lie in [-A_j,A_j], so each row loss
is between zero and `L_j=2*A_j+log(K)`. Set U_j=ceil(2^g L_j) and explicitly
clamp the integer contribution to [0,U_j]. For a row's missingness changing
to present, the same range applies. For add/remove adjacency,
Delta1=sum U_j and Delta2=sqrt(sum U_j²). The inherited conservative
fixed-cohort replacement convention multiplies both by two. Coordinate
maxima are N U_j. Caps, maxima and both workload sensitivities must remain
at most 2^53-1. The inherited outward floating guard applies to Delta2.

Reproduce the exact rational error inequalities:

    python3 inst/cross-grid-family-b/verify_numeric_certificate.py

Circuit simulation, pure-R limb arithmetic and Go integer reference equality
tests supplement this proof; they do not establish production release wiring.
