# B2 protected producer certificate and point ABI

The internal profile `dsvert-dp-irls-producer-p3-q16-q12-v1` admits p=3,
one row per public person slot, and padded C=n from 1 through 64. p=5, p=10,
repeated rows, n=200 and n=1000 are not admitted. These numerical admissions
do not establish B3's separate-process timing or lifecycle availability.
Exactly two pinned source owners, identical to the designated compute pair,
are admitted; adding further custodians requires a new alignment shape.

Each source is a signed Ring128 additive sharing. Protected reconstruction
precedes clamps and narrowing. X and public beta use q16 with coordinate bounds
[-1,1]. With an intercept the circuit sets x0=1; otherwise every X coordinate
has bounds [-1,1]. Offset uses q16 and bounds [-1,1], or is forced to zero for
the signed no-offset mode. The full exact q32 predictor is rounded once to
q16 nearest-even and clamped to [-4,4]. Bernoulli y is an integer with protected
binary handling (a nonbinary value masks only that person's contribution);
Poisson y is an unscaled integer clamped to [0,8]. An absent or malformed
presence slot contributes exactly zero. Neither validity nor clamp-hit counts
are opened. B3 must preserve this personwise masking: releasing validity or
zeroing the entire aggregate upon a single invalid row would invalidate these
sensitivity semantics. The alignment binding is fixed across neighboring data.

The existing grouped q16 sigmoid and range-reduced exp are used as arithmetic
components, pinned to manifest SHA256
`f72e66abaf2e503a809f23d4563418d2889843174109398ae48b02f0ec7edb84`.
The sigmoid is clamped to [0,1], r=y-mu, and
w=clip(RN_q16(mu*(1-mu)),0,1/4). Poisson mu is clamped to
[1200/65536,55], r=y-mu and w=mu. These give enforced R=1,W=1/4
and R=W=55 respectively. The curvature is explicitly a **preconditioner**:
piecewise links and eta clamps do not have the literal reported derivative.
This profile does not qualify sampling inference.

Score products are exact q32 and w*x_i*x_j products exact q48, with the upper
triangle in row-major order. One row is one person, so person rounding is one
nearest-even operation: divide raw score by 2^20 and raw H by 2^36 to get q12
integers. The physical rounding slack is 3/8192 for g and 3/4096 for H.
R*4096 and W*4096 are integer endpoints fixed by monotone nearest-even rounding.
Thus exact per-person coordinate caps are (4096,1024) for binomial and
(225280,225280) for Poisson. This proves tighter integer bounds than the generic
half-unit triangle bound. Add/remove S1_g,S1_H are (12288,6144) and
(675840,1351680); replace-one doubles them. Each lane uses its own S1.
Translations are exactly A_j=C*cap_j and U_j=2*A_j. Translation is added once
to the aggregate. All-zero data decodes to zero; endpoints are legitimate
noiseless extreme values and trigger B1's saturation marker if later released.

The largest exact dot is 4*2^32, raw score is at most 55*2^32, and raw H is at
most 55*2^48 <2^54. Even the looser 64-row raw H sum is <2^60, within signed64.
Translated q12 aggregates are at most 2*64*225280 <2^25, strictly below 2^127.
Ring128 source reconstruction and output masking are modular by definition;
all deterministic statistical arithmetic after clamps has the bounds above.
This certificate does not promise no wrap for unbounded future v4 noise draws.

For exact encoded X,beta,offset, eta rounding error is <=1/131072. Sigmoid's
uniform error at q16 eta is 69/327680; exp's is <=11/2000. Knot enclosures,
interpolation bounds, ln2 reduction and deterministic ranges are checked using
exact rational arithmetic by `inst/certificates/dp_irls_b2_certificate.py`.
With Lipschitz constants 1/4 and 55, and q12 rounding, each physical score
coordinate differs from the clamped mathematical equation by at most
877/2621440 (binomial) or 98987/16384000 (Poisson). H errors are
897/2621440 and 98987/16384000, adding binomial q16 weight rounding.
Errors are relative to encoded source values: source materialization must
separately justify any conversion from real-valued original data in B3.

`dpIRLSProducerCertificate` emits integer-string/rational canonical JSON;
its digest hashes `dsvert-dp-irls-producer-certificate-v1`, one NUL byte,
and those bytes. R mirrors it in `.dsvert_dp_irls_profile_certificate`.
`.dsvert_dp_irls_profile_admit` verifies unanimous signed B1 contract pins and
exact producer constants. B1's deliberately synthetic fixtures remain valid
public-arithmetic contracts but cannot authorize this producer.

`.dsvert_dp_irls_stage_plan` uses the private durable B1 store, validates the
entire dual-signed predecessor chain and recomputes every prior canonical
update. It selects beta0 or the committed successor; caller beta claims must
match exactly. The plan contains q16 integer beta, root, predecessor, stage ID,
purpose, stage index, family, dimensions, intercept/offset mode and certificate
digest. The point digest hashes `dsvert-dp-irls-public-point-v1`, one NUL byte,
and canonical JSON with keys beta,predecessor,purpose,root,stage_id,stage_index.
The cross-grid session binds the full plan. This internal helper is not a
DataSHIELD method and performs no source reads or releases.

`dpIRLSExecuteStage` checks that the prepared point and certificate generate
the exact durable graph before executing it. The single stage stores the
ordered g/H shares together with their protected validity. Retries recover
the retained COMMIT; a different point fails before transport I/O. Protocol
component durations are optional local observations, not public diagnostics.

Independent exactness tests exposed two negative-literal compiler defects.
The producer avoids signed Ring128 comparison against a negative literal by
decoding the unsigned sign/magnitude before narrowing. It emits negative
public-beta products as subtraction of products with positive constants,
avoiding zero extension of a negative int32 literal into int64. These are
source-generation workarounds under the existing compiler pin, with boundary
and fractional-coefficient regressions; the underlying compiler is unchanged.

B2 admits the numeric profile ID above. B3 must add admission for the named
`irls-smoke-k2-c64-p3-v1` only after checking its complete frozen path: C=64,
p=3, binomial/intercept, zero start, T=2, both curvature refreshes, terminal
audit, split budgets (1,1),(1,1),(2,2), total epsilon=8, box [-1,1], floor=8/5,
ridge=0, and damping/trust=1. Merely adding a name alias is insufficient.
The simulator-selected showcase and larger public shapes remain unadmitted.
