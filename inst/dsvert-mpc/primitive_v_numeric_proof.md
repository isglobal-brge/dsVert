# Primitive V additive numeric certificate

Profile `primitive-v-taylor12-exp64-atanh20-q64-v1` uses the frozen f50 source
encoding, q64 nonlinear scale and signed 192-bit arithmetic. It changes no V1
coefficient or evaluation order: coupled families explicitly sign this new
profile. Every division and q64 product rounds nearest, ties to even. Let
`u=2^-64`. Public compiled constants are exact rational roundings, except ln2,
whose q64 integer is `12786308645202655660`.

## Exponential and prefix log-sum-exp

For encoded eta in [-17,17], set x=RN(eta/64), evaluate the degree-12 Taylor
polynomial for exp(x) with q64 coefficients by Horner, then square six times
with q64 rounding. The core input has |x|<r=133/500. The core remainder is
at most `(4/3)*r^13/13!`: exp(r)<4/3 follows from
`exp(r)<=1+r+r^2/[2*(1-r/3)]<4/3`. Coefficient rounding and Horner rounding
together are at most `u/(1-r)`. Core argument rounding contributes at most
`(2/3)u`. Thus `E0=(4/3)*r^13/13!+u/(1-r)+(2/3)u <7.257e-18`.
The exact unrounded core is at least 3/4, so the initial relative error is at
most `R0=(4/3)E0`. After square i, the relative error satisfies
`Ri <= 2*R(i-1)+R(i-1)^2+(u/2)*Bi`, where safe upper bounds on inverse exact
squares are B=(2,3,9,71,4915,24154953). These respectively bound
exp(17/32), exp(17/16), exp(17/8), exp(17/4), exp(17/2), exp(17).
Exact rational recurrence gives R6<6.557e-13<7e-13.
The test certificate checks the transcendental B inequalities using rational
Taylor upper bounds, and checks the full recurrence as rational arithmetic.

Positive q64 exponential integers are summed exactly. If a prefix has k live
terms, its absolute sum error is at most `R6*sum(exp(eta_i)) <= k*exp(17)*R6`,
while its relative error is at most R6, regardless of k<=16384. This distinction
avoids an error bound amplified by exp(34) near the lower endpoint.

The logarithm first obtains `m in [1,2)` and integer exponent k by secret,
fixed-schedule power-of-two normalization. A right shift introduces less than
one q64 ulp in m; left shifts are exact. Then z=RN((m-1)/(m+1)), and
`log(m)=2*sum_{j>=0} z^(2j+1)/(2j+1)` is evaluated through j=19, using Horner
in RN(z*z). The true |z|<=1/3; its rounded value is <1/3+u/2. The truncation
error is at most `2/(41*3^41*(1-1/9)) <1.505e-21`.
For a deliberately loose roundoff bound, perturbing z by u/2 changes the
polynomial by less than 2u; perturbing z^2 by u/2 changes it by less than 2u
(the sum of absolute derivatives is bounded by the corresponding geometric
series at 1/8). Twenty coefficient roundings and nineteen Horner roundings
contribute less than 40u after the final multiplication; that multiplication
adds u/2. Normalization adds less than 2u in log, and |k|<=64 multiplies the
ln2 constant error by at most 32u. Total log error is below 80u plus the tail,
hence strictly below 3e-17. The supported positive encoded log input is <2^127.

Consequently every nonempty prefix LSE differs from the exact LSE of its
encoded inputs by at most `R6/(1-R6)+3e-17 <7.001e-13`. For original bounded
real features/coefficient inputs, log-sum-exp is 1-Lipschitz in the infinity
norm: its gradient is nonnegative and sums to one. Add the frozen V1 predictor
encoding error 1.4655e-14 to obtain a uniform bound <7.2e-13 per prefix,
independent of n. Adding up to n event contributions introduces at most
`n*(7.2e-13+1.4655e-14)` before output quantization. Empty prefixes have a zero
sentinel and secret zero exponential sum; a consuming Cox circuit rejects an
event with an empty risk set. No log(0) result is used.

`primitiveVExpNegativeQ64` supports max-shifted GLMM node scores on the entire
negative half-line. Below -32 it outputs zero; otherwise it squares
ExpQ64(RN(x/2)). On nonpositive input each squaring propagates absolute error
as `E'=2E+E^2+u/2`, giving six-square error <4.662e-16. The additional square
and halving roundoff yield <9.324e-16. Cutoff error is exp(-32)<1.3e-14, so
absolute error is uniformly <1.4e-14. With Q max-shifted scores, at least one
exponential is exactly one, and the sum is >=1. Thus the integrated log error
from negative exponentials is bounded by `Q*1.4e-14/(1-Q*1.4e-14)`, plus the
log evaluator error. Approximation of Gauss-Hermite integration itself is a
separate modeling/quadrature error and is not claimed to be covered here.

## Reductions, widths and private shape

Plain sums are exact over encoded words. Segmented sums reset on private
boundary bits. Segmented squared sums compute RN(x_i*x_i/2^64) before summing;
the error relative to squared encoded values is at most `k*u/2` for k terms.
If each original real value has absolute magnitude <=B and encoding error e,
its squared-value error is at most `2*B*e+e^2+u/2`; multiply by k for a segment.
The emitter returns fixed n-slot vectors, with segment totals at tails and
secret zeros elsewhere, plus a secret validity expression requiring start[0].
The caller must validate raw boundary bits, value caps and alignment, and mask
all output coordinates with their joint secret validity. These helpers never
reveal segment count, starts, tails, prefix values or sum outputs.

With |x|<=2^24 and n<=16384, reduction inputs have magnitude <=2^88, raw
squares <=2^176, global sums <=2^102 and squared sums <=2^126. Exponential
results are <2^89, sums <2^103, and conservative nonlinear raw products are
<2^179. Log normalization and atanh products are <2^131. Thus signed int192
has at least 12 sign-safe bits of headroom at the largest conservative raw
bound. A consumer squaring a segment sum must impose its own tighter bound;
the reduction width claim does not certify that additional operation.

Every helper's schedule depends only on public size/profile. The Go reference
rejects malformed shapes with a fixed error. In-circuit failures are secret
bits incorporated into the caller's masked output, never public exceptions.

The emitted implementation narrows unsigned magnitude temporaries to reduce
GC cost, while preserving every integer result and rounding above. Generic
q64 multiplication requires operand magnitudes <2^95 and uses existing
`wideMul(uint96,uint96)` to obtain the full 192-bit product. Exp Horner
magnitudes are <(4/3)*2^64, and log Horner magnitudes are <(9/4)*2^64; both
fit uint66. Their exact products use uint132. Exponential squaring operands
are at most exp(17/2)*2^64 plus certified error, below 2^77; uint80 operands
and uint160 products suffice. Exp's /64 and negative-exp's /2 are signed
nearest-even shifts of a uint72 magnitude (input magnitude <=32*2^64).
For the log ratio, `(m-1)*2^128 <2^128`, while `(m+1)*2^64 <3*2^64`;
unsigned128 division/remainder is exact. All final family arithmetic and input words remain int192. The frozen V1
Ring128 feature/outcome transport remains unchanged; its values are widened
at the new circuit boundary. These are compiler-local width refinements, not
changes to the fixed-point ABI.
