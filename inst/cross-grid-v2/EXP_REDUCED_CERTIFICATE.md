# Range-reduced Poisson candidate (not admitted)

This is a new arithmetic identity, not a reinterpretation of the V1 q64 ABI.
Source features and public coefficients remain f50; the proposed complete exact
f100 dot product is rounded once to eta26 and projected to its public domain.
The component tests start at eta26; they do not implement that dot product.

For an eta26 integer x, choose k by nearest-even rounding of
`x * round(2^30/ln(2)) / 2^56`. The signed k lies in [-23,23]. Form
`r = round_even((16*x - k*round(2^30*ln(2)))/64)` at f24.
The reciprocal approximation perturbs eta/ln(2) by at most 16/2^31.
Even when k differs from the ideal nearest integer at a boundary, the actual
residual has magnitude at most

`ln(2)*(1/2 + 16/2^31) + 23/2^31 + 1/2^25 < 1/2`.

Thus no exact-k assertion or data-dependent fallback is needed. The residual
argument error relative to eta-k*ln(2) is at most 23/2^31+1/2^25.
The complete-dot encoding and eta26 rounding budget is
33/2^51 + 16/2^102 + 1/2^27.

On [-1/2,1/2], K equal binary intervals select an endpoint/midpoint quadratic.
Three nonnegative coefficients at f27 fit signed32. Both Horner multiplications
use exact unsigned64 temporaries and nearest-even rounding by the binary
interval width. Polynomial words are <=32 bits; raw products are not rounded
or truncated until their documented division. The analytic interpolation
error is exp(1/2)/(72*sqrt(3)*K^3). Three coefficient roundings and two product
roundings contribute at most 5/2^28. The interval generator encloses every
coefficient and bound using outward mpmath intervals.

Scale the mantissa by 2^k and round once to f16. The circuit starts from the
mantissa shifted left 12 and shifts right by 23-k, accumulating guard/sticky
bits through a six-stage barrel shifter. It then rounds ties to even once.
The reconstructed value needs 40 bits at eta=16; it is carried in uint64.
This does not claim that the full-domain f16 exponential fits a 32-bit word.
All polynomial state remains within 32 bits, as required by the arithmetic
route. Bounds on reciprocal and residual products are <2^61 and <2^35.
The reduced residual fits signed30, so low-32 subtraction and signed recovery
are exact even when the intermediate unsigned subtraction wraps.

Let E be the interpolation-plus-arithmetic bound and d the total input-plus-
reduction error above. A uniform relative exponential bound is
`exp(d)*(1 + exp(1/2)*E) - 1`.
For public A and outcomes through 1024, the pre-output-rounding loss bound is
`exp(A)*relative_error + 1024*eta_error + 1/65536`.
The last term covers the exponential shift and f16 log-factorial rounding.
Final loss quantization adds at most 1/131072. Clamping is nonexpansive.

Caps in the fixture are ceil(65536*(real_loss_bound+2*loss_error)), where the
real bound is the outward maximum at the four (eta,y) rectangle corners.
They enclose approximated loss plus its certified error. Integer clamping
then gives U, Delta1=a*sum(U), Delta2=a*sqrt(sum(U^2)), with the frozen adjacency
multipliers. These are proposed envelope caps, not production signed caps.

K=64 has certified loss errors 0.0000317234243 at A=4 and 1.43799821 at A=16.
The R utility regression covers the proposed A=4 default with 16 equal-envelope
candidates, n=2000 and epsilon<=8: the total error is below 1% of Delta2/epsilon.
It is not a calibrated production-noise test or a claim for all possible grids.

Reproduce from dsVert:

```
python3 inst/cross-grid-v2/generate_exp_reduced.py --check
Rscript inst/cross-grid-v2/validate_exp_reduced.R
(cd inst/dsvert-mpc && go test -run '^TestCrossGridExpReducedV2' -v -count=1)
```

The pure R oracle splits the 61-bit reciprocal product into exact binary64-safe
limbs. Go independently uses big.Int for every rounding. Shared fixtures and
dense/high-precision tests supplement the analytic proof, not replace it.
