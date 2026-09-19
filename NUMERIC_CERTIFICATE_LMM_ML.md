# Finite ML variance-grid arithmetic

This certifies the component arithmetic below. It does not establish a release
promotion, an n2000 capacity admission, or REML support. The fixed-covariance
`grouped-lmm-stats-f264-q64-v2` objective and implementation are retained.

Profile: `grouped-lmm-ml-variance-f264-q64-log-up-v1`.
Canonical manifest: `inst/certificates/grouped_lmm_ml_v1.json`.
SHA256 of recursively key-sorted compact JSON, excluding the trailing newline:
`0f93bcef61647e6810bb5691f09563c8758c75b25f7d86de03d37ada3cd6bea5`.
The signed R numeric descriptors verify the complete installed file, including
its trailing newline, against raw-file SHA256
`6c6f0c3f5413396494de455f8d240753d9f72256f3f09dbf931752c57855033e`.
Both package copies contain those same bytes; the two hash domains are explicit.
Every ML stage binds this digest, the complete typed specification, and all
generated public log-table integers in its profile digest and receipt.

## Objective and admitted domain

For the private live rows of cluster c, let n be its live count, r=y-X beta,
and V=sigma² I+tau² 11'. Each public coefficient/variance candidate computes

    Q_c = r' V^-1 r + log|V| + n log(4).

The empty cluster has Q_c=0. This is twice the Gaussian marginal negative log
likelihood after dropping n log(2 pi) and adding n log(4). Both adjustments are
candidate-independent. The finite grid evaluates signed public beta candidates
and public variance pairs; it does not perform an unbounded optimizer or a GLS
fit outside that grid. Each cluster contribution is clamped to its signed
candidate cap and quantized once before exact cluster accumulation.

Variance pairs are strictly increasing lexicographically by (sigma²,tau²),
without duplicates. Coordinates are variance-major, then the original signed
beta order. There are at most 256 coordinates in the internal arithmetic ABI;
the authenticated release contract may impose a smaller bound.

The domain is B<=32, normalized x,y in [0,1], sigma² in [1/4,16], tau² in
[0,16]. Variances are exact q16 lattice values encoded at q64. The existing
coefficient bounds and f50 encoding slack are unchanged. `Objective=""`
requires an empty variance grid and retains the historical quadratic exactly;
`Objective="ml"` requires the finite variance grid. REML is rejected.

## Exact quadratic and log addition

The product and sufficient-statistic stages run once. Each variance branch
reuses those moments and the retained RN-even q64 reciprocal/lambda tables,
f164 precision Gram, exact signed Ring192-to-Ring384 lift, and f264 quadratic.
The retained proof in NUMERIC_CERTIFICATE_GROUPED.md bounds these operations
by less than 7e-11 before output quantization on original bounded inputs.

For n>=1 the shifted determinant is

    D[n] = (n-1) log(4 sigma²) + log(4(sigma²+n tau²)).

Each argument is in [1,2112]. The complete public table D[0..B] is generated
without a floating-point logarithm, then selected by the private f50 live count
inside GC. A malformed/nonintegral count clears private validity. Neither the
count, selected log value, nor validity is opened.

The selected q64 log share is added to the f264 quadratic before clamping or
rounding. Multiplication by 2^200 is a valid additive map from Ring192 to
Ring384: changing a representative by 2^192 changes its image by 2^392, which
is zero modulo 2^384. Thus the low Ring192 limb stays unchanged and the high
limb adds the local log share times 2^8 modulo 2^192. This step does not locally
extend a secret sharing by an invalid zero-extension.

## Rational log certificate

Reduce x=2^k m exactly with 1<=m<2 and 0<=k<=11. Then
z=(m-1)/(m+1) lies in [0,1/3), and

    log(m) = 2 sum_{j=0}^{31} z^(2j+1)/(2j+1) + R,
    0 <= R <= 2 z^65 / (65(1-z²)).

The same identity with z=1/3 encloses log(2). All sums, products, and tail
bounds use exact rational arithmetic. The largest combined interval width
for D[n] is bounded by 32*12 times the tail at z=1/3, which is strictly less
than 2^-80. Runtime generation also checks that exact inequality for every
table entry. The table stores ceil(2^64 times the rational upper endpoint), so

    0 <= table[n]/2^64 - D[n] < 2^-64 + 2^-80 < 2^-63.

D[0] is exactly zero. Existing quadratic error plus this log error remains
below the outward 1e-8 pre-quantization allowance. Clamping is nonexpansive;
final nearest-even quantization adds at most 1/(2*2^g), g=8..18.

The shifted determinant is nonnegative. Each log argument is at most 2112,
which is below 2^12; the rational enclosure establishes log(2)<1. Therefore
D[n]<12n<=12B. The table's upward rounding is also checked below 12n.
A conservative natural cap for beta j and variance v is

    B * R_j² / sigma_v² + 12B + 1e-8,

where R_j is the signed normalized-domain residual bound before encoding.
Multiplying by 2^g and rounding the cap outward gives the candidate's integer
cap. The finite approximation error already covers f50 encoding.

## Privacy and scope

Per-cluster [0,U_j] clipping retains the existing patient adjacency proof:
add/remove changes one cluster and replacement/movement changes at most two.
For the complete variance-major coordinate vector, Delta1=a sum(U_j) and
Delta2=a sqrt(sum(U_j²)), with a=1 or 2. The existing private validity gate and
sticky DP handoff remain mandatory. No statistic, live count, log determinant,
or intermediate validity is a release.

REML additionally requires the global private design-information determinant
and a corresponding GLS/profile calculation. The current signed cross-owner
domain supplies no positive-definiteness certificate for that private matrix.
The explicit ML alternative above makes no REML claim.

The Go tests check the uniform rational tail inequality, all table counts at
domain edges against an independent 256-bit/180-term reference, canonical
variance order, one shared product/moment graph, and real two-authority
integer oracle equality with private invalidity, fresh attempts, bilateral and
unilateral recovery, and cold replay. These component checks do not replace
the full authenticated release and capacity gates.
