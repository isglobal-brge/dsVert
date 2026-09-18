# Numeric certificate — cross-owner NB2 v1

The Day1 reviewer decision supersedes the earlier q64 degree 256 nonlinear
circuit. This extension preserves the source f50/f100/q64 ABI, theta domain,
private validity, integer output lattice and correct NB2 likelihood. The
nonlinearity now evaluates a certified q16 piecewise quadratic with 32-bit
words and two multiplications. Exactness means exact evaluation of this
profile; it does not mean exact transcendental evaluation.

The eleven supported signed public theta values remain 2^k, k=-3..7.
Outcomes remain integers 0..M with M<=1024; coefficient magnitudes<=8 and
L1<=16, predictors 1..16, output g8..18. Unsupported parameters fail closed.

* NB profile identity: `cross-grid-nb2-softplus-pwq64-q16-domain22-v1`.
* Reusable softplus identity: `cross-grid-softplus-pwq64-q16-symmetric-tail16-v1`.
* Profile SHA256: `36771f85ecc4edf240dc49a8fc2d49345f314ec5c8e758f4a918532902b3da17`.
* Certificate SHA256: `1b21c0b8fe91b0f2f280c273469aaf0bad6a4deae176e3db2559ee83beea7dfd`.

Hashes cover recursively sorted compact JSON. Reproduce the public artifact:

```sh
python3 inst/cross-grid-nb/generate_numeric_profile_nb_v1.py inst/cross-grid-nb/numeric_profile_nb_v1.json --check
```

The generator uses mpmath 1.3.0 with 90-digit outward intervals. The analytic
inequalities establish a uniform certificate; dense test points supplement it.
The profile data in the server and client packages are identical.

## Correct NB2 likelihood and constants

With mu=exp(eta), the negative log PMF is

    C(theta,y)+(y+theta)*softplus(eta-log(theta))-y*eta,
    C(theta,y)=log Gamma(theta)+log Gamma(y+1)
               -log Gamma(theta+y)+y*log(theta).

This includes the full y-dependent log(theta+mu) term. For theta 2,y 1,eta 0,
the exact loss is log(27/8). The real-arithmetic equivalent form using
y*softplus(log(theta)-eta) needs no distinct transcendental kernel. It is not
an interchangeable integer evaluation order: shifting the linear term from
the q64 argument to the rounded q16 argument changes the loss unless the
rounding difference is corrected. The pinned integer oracle and producer
must retain the assembly below (or prove exact integer equality with it).

The public artifact retains q64 log(theta) and C(theta,y) constants.
C(theta,0)=0 and C(theta,y)-C(theta,y-1)=log(y)-log(theta+y-1)+log(theta).
Each table entry is certified within 2^-64 of its real value. The outcome
owner may compute/select its private cleartext constant and provide shares.
The self-contained circuit equality adapter privately selects the same table
from y; production should use the fused producer's authenticated share path
for constants and linear products. The private constant is never public.

## Piecewise profile and analytic bound

For z=eta-log(theta), first round the complete q64 argument to q16, nearest,
ties to even. Write x=abs(z_q16)/65536. For 0<=x<16 choose the public interval
j=floor(4x), j 0..63, and local coordinate r=x-j/4. Let h=1/4 and
f(x)=log(1+exp(-x)). Interpolate f at jh,jh+h/2,jh+h:

    A=f(jh), B=(-3f(jh)+4f(jh+h/2)-f(jh+h))/h,
    C=(2f(jh)-4f(jh+h/2)+2f(jh+h))/h^2.

The public A,B,C are rounded to q16 with ties to even. In integer arithmetic,
with r_q16=abs(z_q16) mod 16384:

    t=round_even(C_q16*r_q16/65536),
    residual=A_q16+round_even((B_q16+t)*r_q16/65536).

For x>=16 set residual 0. Return residual+max(z_q16,0). Public breakpoints
and coefficients are explicit in the profile. Piece selection is a comparison
and mux tree; no secret-dependent host indexing occurs in the circuit.

The exact third derivative satisfies |f'''|<=1/(6*sqrt(3)). The product of
three interpolation factors is bounded by h^3/(12*sqrt(3)), so the quadratic
interpolation remainder is at most h^3/1296=1/82944. Coefficient rounding
contributes at most(1+h+h^2)u/2=21u/32, where u=2^-16. The two rounded
products contribute at most (h+1)u/2=20u/32. Argument rounding contributes
at most u/2=16u/32 because exact softplus is 1-Lipschitz. Their sum is 57u/32.
The tail residual is at most exp(-16)<0.000000113. Summing these terms
conservatively gives

    E_soft <=1/82944+57/(32*65536)+0.000000113
            <0.00003936.

At rounded arguments across the tail join, use the tail bound at the rounded
argument and the same Lipschitz argument-rounding term. The profile domain
[-22,22] contains all shifted eta values, including q64 source-encoding slack
and both extreme theta values. The q64 log(theta) contribution, at most 2^-64 inside softplus, is
absorbed by the strict slack below the outward 0.00003936 bound.

All public-table operands and profile results fit signed32. Specifically,
|z_q16|<2^21, |A|,|B|,|C|<2^16, 0<=r<2^14. Both raw polynomial products
are strictly below 2^30. The Boolean implementation uses an equivalent
unsigned magnitude form: A is 16 bits, -B is 15 bits, C is 13 bits and r is
14 bits. Both products fit 29 bits; every profile word is at most 32 bits.
The generator verifies nonnegative inner magnitude and these tighter bounds.
Symmetric ties-to-even rounding makes this exactly equal to signed Horner.
Constant and linear assembly retains signed192/q64 to preserve the frozen source ABI;
that width is not used for the profile polynomial.

## Loss assembly, error and utility

The complete predictor is formed once at f100, with intercept once, then
rounded once to q64. The frozen bound is

    E_eta=33*2^-51+16*2^-102+2^-65 <0.000000000000014655.

Promote soft_q16 to q64 by an exact left shift 48. Form

    loss_q64=C_q64+round_even((8*y+8*theta)*soft_q64/8)-y*eta_q64.

The multiplication by 8*y+8*theta and division by 8 are exact for this promoted
profile, but 2^-63 conservatively covers constant and assembly slack. The
weighted log(theta) uncertainty is already included in the softplus bound.
NB2 has |d loss/d eta|<=max(y,theta)<=1024. Therefore for a signed cap M,

    E_NB(M,theta)=(M+theta)*0.00003936
                  +1024*0.000000000000014655+2^-63,
    E_NB(1024,128)<0.045343.

The previous claim that error is below one quarter of a g18 output ulp is
withdrawn. Final output quantization adds at most 1/(2*2^g). Clamping is
nonexpansive. Thus every unclamped exact loss is approximated within
E_NB+1/(2*2^g) when the signed cap encloses the certified domain. Aggregation
adds at most N times this bound. The mechanism selects a DP-best candidate
for this bounded approximate loss; approximation contributes at most twice
the aggregate bound to an exact-loss excess-risk comparison.

Tests assert that N 10000 times the uniform profile loss error stays below 1%
of the Laplace vector noise scale for the certified default envelope:
50 candidates, A 16, M 1024, theta 128, epsilon 1,4,8. This is a statement about
that envelope, not arbitrary tiny grids or low caps. Tests cover an independent
high-precision NB2 oracle, all theta values, all g, signed eta encoding slack,
dense profile points, breakpoints on both sides, and q16 half-ulp ties.

## Caps and sensitivity

The real NB loss is convex in eta, so for every y 0..M its maximum on[-A,A]
is attained at an endpoint. The R cap builder evaluates the public integer
profile at both endpoints and all bounded y, with an upward-rounded public
constant. Its q16 coefficient products are exactly representable in binary64
(their magnitudes are below 2^30). Decimal long division converts each q64
constant to an upward q16 integer, avoiding an uncertified lgamma result.

The public endpoint evaluation allowance is

    E_endpoint=(M+theta)*(0.00003936+2^-16)+2^-20.

The extra q16 ulp encloses public endpoint/argument conversion;2^-20 encloses
the remaining public linear arithmetic over these bounded operands. This
allowance makes the maximum evaluated endpoint plus E_endpoint an upper
bound on the exact maximum. The signed natural cap adds 2*E_NB, so it bounds
max(profile_loss)+E_NB as required by Day1. Finally U=ceil(2^g*loss_bound).
The exact per-row clamp independently enforces 0<=integer_loss<=U.

For adjacency factor a 1 add/remove or a 2 replacement:

    Delta1=a*sum_j U_j,
    Delta2=a*sqrt(sum_j U_j^2),
    coordinate maximum_j=N*U_j.

The existing outward L 2 guard remains mandatory. All integers, maxima and
sensitivities must satisfy the frozen 2^53-1 representability check. The
approximation changes utility and cap derivation, never epsilon, delta or
the adjacency guarantee.

## Engine cost and remaining gate

The generation-one wide-spline machinery uses runtime floating coefficients,
a different truncation/share protocol and an uncertified domain. It cannot
be substituted for this signed exact profile without separate proof and
protocol wiring. This implementation therefore emits the Boolean profile.
`TestCrossGridNBV1SoftplusCircuitCostAndEquality` measures actual compiled AND
count and garbled bytes and checks profile equality across the piece table.
The measured optimized profile uses 5,720 AND gates, 17,989 total gates and
183,056 garbled table bytes per evaluation (AND 2, OR 3, INV 1 labels of
16 bytes). For 500,000 evaluations this is 91.528 GB, excluding OT and framing.
It exceeds the Day1 2,000 AND / approximately 30 GB target: the production
cost-acceptance requirement remains unmet and the production gate stays closed. This is a measured limitation, not a waiver.
The first 32-bit operand implementation used 9,135 AND gates; narrowing the
exact same profile operands improved cost without changing any signed bytes.
The full NB adapter additionally includes the private constant table and
linear products; it is an equality adapter, not the production cost model.

The sole integration hook remains `exactGCRegisterNBLossV1`. Its kernel exposes
both the complete row adapter and the reusable softplus component. The fused
producer must perform share-side constant/linear assembly, preserve private
terminal guards and pass its authenticated release/cost acceptance gates.
No command or production release is enabled by this family registration.

The pinned MPCL compiler mishandles direct casts of wide negative decimal
literals. The NB emitter therefore emits their explicit 192-bit two's-complement
positive bit pattern. Constant-folded subtraction also triggers a compiler
panic, so the emitter does not use it. Its eta guard compares a nonnegative
magnitude to the positive bound and explicitly rejects the signed minimum. Compiled tests
exercise negative log(theta)/constant tables, both domain endpoints, the
one-integer-outside slack cases and signed-minimum input; no shared compiler
or same-owner route is changed.
