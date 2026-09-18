# Candidate piecewise quadratic arithmetic (not admitted)

This is an arithmetic/cost experiment for Step 2. It is not a production kernel,
not a DP mechanism, and does not enable either cross-owner release route.

The generator creates 30 public profiles: binomial/Poisson, A=1,2,4,8,16,
K=16,32,64. Input eta is rounded once to f16 from the complete f100 dot product,
then projected to [-A,A]. Features and coefficients retain the V1 f50 ABI.
The candidate nonlinear output uses f16 except Poisson A=16, which uses f6
because exp(16) cannot fit in a 32-bit f16 word. This is an explicit proposed
profile change; old V1 signatures and the q64 integer oracle remain unchanged.

Each interval has width h=2A/K. The polynomial in local t=(eta-left)/h is
P(t)=c0+c1*t+c2*t*t, interpolating the real function at 0,1/2,1. The interval
DCT is not reused: mpmath outward intervals enclose the three function values
and the coefficients. Both coefficient interval endpoints round to the same
nearest-even integer. Horner evaluation performs exactly two rounded products,
using nonnegative 32-bit coefficient/state words and exact 64-bit raw products.
The generator proves every state <2^31 and every raw product <2^63. The probe
uses the frozen nearest-even rule, including product ties. Endpoint eta=A uses
the last interval with t=1, never an extrapolated tail.

For f''' bounded by B, interpolation error is at most B*h^3/(72*sqrt(3)).
This follows from the degree-two interpolation remainder and
max_[0,1] |t(t-1/2)(t-1)|=1/(12*sqrt(3)). For softplus B=1/(6*sqrt(3));
for exp B=exp(A). Three rounded coefficients and two rounded products add
at most 5/(2*2^f). Projection cannot increase error relative to a real eta
in [-A,A]. The V1 encoding error is at most 33*2^-51+16*2^-102; the new eta
rounding adds 2^-17. The loss derivative bound is 1 for binary outcomes and
exp(A)+1024 for Poisson. The log-factorial table is independently interval
rounded, adding at most 1/(2*2^f) to Poisson loss error. The JSON loss_error
is an outward decimal bound on the sum. Output-lattice rounding and summation
would add n/(2S) and multiply the per-row loss error by n, respectively.

The certificate is analytic; dense R/Go checks and independent 256-bit Go
references are regression evidence, not its proof. Caps in the fixture are
conservative profile-envelope caps, not replacements for the V1 signed caps.
They use U=ceil(2^16*(L+2*error)), enclosing max approximated loss plus error.
L is enclosed using interval arithmetic at the extrema: softplus(A), or the
four corners of [-A,A] x [0,M] for Poisson. Convexity in both variables proves
the latter bound. Add/remove sensitivity is sum(U) and sqrt(sum(U^2)); the
existing conservative replacement multiplier remains 2. Production must also
check whole-workload maxima, scale, adjacency and <=2^53-1 representability.

Reproduce from the package root:

```
python3 inst/cross-grid-v2/generate_profile.py --check
Rscript inst/cross-grid-v2/validate_profile.R
(cd inst/dsvert-mpc && go test -run '^TestCrossGridPWV2' -count=1 -v)
Rscript inst/cross-grid-v2/benchmark_profile.R .
```

The Boolean constant-folding pass is test-only, applies truth-table identities,
shares duplicate expressions and removes unreachable gates. Exhaustive 8-bit
input-pair checks and profile boundary/random checks compare its results.
No production compiler setting or generation-one code is changed. The probe
compiles one shared nonlinear input, returns a masked value and an unmasked
validity bit, and measures real Yao/KOS protocol traffic over encrypted
net.Pipe connections. This interface is deliberately NOT a release interface:
full private validity handling, f100 dot products, log-factorial selection,
loss assembly, shared sums, DP noise, signed source/result bindings, exactly-once
injection and crash recovery are not implemented by it.
