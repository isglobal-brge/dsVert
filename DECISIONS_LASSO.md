# LASSO cross-owner decisions

1. LASSO is public postprocessing of a signed finite base release. It has no new
   per-row GC kernel. Binomial/Poisson inherit the frozen kernels, ABI, validity,
   alignment, caps and numeric certificates. Gaussian inherits its existing
   sufficient-statistic route; it is never represented as a GC loss vector.
2. All candidate betas and lambdas are public and signed by both custodians.
   Candidates are ordered by decreasing lambda then canonical beta JSON. The
   intercept is unpenalized. Bounds are lambda in [0,8], |beta_k|<=8,
   sum|beta_k|<=16, one through 256 candidates and at most 16 predictors.
3. Distinct lambda/beta pairs can share beta. A canonical unique base beta grid
   is released once, and public candidate indices reuse its coordinates. Adding
   lambda values does not duplicate base sensitivity or protected evaluation.
4. Public penalty is exactly P_j=ceil(N*2^g*lambda_j*sum_{k>0}|beta_jk|) for
   the signed binary64 values, with P_j<=2^53-1. Pure-R base-2^15 integer
   arithmetic decodes binary64 mantissas/exponents, forms the exact rational,
   and computes its ceiling. Subnormal positive inputs therefore cannot silently
   become zero. This definition avoids a binary64 multiplication slack bug.
5. N is signed public capacity, not released/protected complete-case count.
   Binomial/Poisson objective is (noisy base NLL+P_j)/(N*2^g). Gaussian objective
   is (half noisy RSS+P_j)/(N*2^g), matching glmnet's half-RSS convention on
   normalized variables. Noisy RSS may be negative; no implicit optimizer or
   PSD projection is introduced.
6. Exact base sensitivity is unchanged: P_j is independent of every protected
   record and cancels between adjacent datasets. Candidate mapping, penalty
   addition and selection are deterministic DP postprocessing. The contract
   explicitly records zero additional L1/L2 sensitivity, not a weakened base
   epsilon, delta or cap. A joint release of reused coordinates has only the
   sensitivity of the unique base release.
7. Authentication is composed rather than duplicated. The LASSO wrapper signs
   the complete base digest and reconstructed public extension. The default
   validator authenticates frozen GLM contracts. Gaussian integration must call
   its existing authoritative manifest/certificate validators first. Production
   entry points fail closed until the fused source/result/noise/receipt adapter
   is connected. Internal public algebra helpers do not authorize releases.
8. Two participating owners must be exactly the two compute/noise authorities.
   A three-peer frozen contract is not accepted by this family adapter.
9. Same-owner finite LASSO and sealed generation-one implementations are untouched.
   No push or thesis modification is part of this change.


## Day 1 arithmetic addendum — 2026-09-18

10. The binding reviewer decision preserves this public penalty unchanged. For
    binomial/Poisson, replace decision 1's historical kernel dependency with the
    certified low-precision piecewise-polynomial base producer. Preserve the
    frozen source ABI and required state strings. Profile identity, approximation
    caps and error are authenticated by that producer's validator, supplied at
    the one family registration seam; this lane does not invent a second base
    numeric profile. The currently available frozen contract validator is a
    staging/authentication test dependency and does not authorize execution of
    the rejected q64 route.
11. The LASSO certificate now uses the producer's full per-row error E_j. Public
    capacity-normalized objective error is < E_j+1/(N*2^g), excluding DP noise
    and final binary64 public arithmetic. The Step-1 3/(4*2^g) bound is not
    asserted for the replacement producer. Gaussian retains its established
    exact moment pipeline and certificate.
12. Both package adapters additionally bind lattice precision to the signed
    policy and computation identities to the pinned two custodians. Gaussian
    adapters enforce the existing common lattice, count/XTX/XTy/yty coordinate
    order, dimension and capacity maxima before evaluating half RSS. Existing
    Gaussian manifest/certificate validation remains mandatory at integration;
    these consistency checks do not replace its authentication.
13. Regression evidence covers exact public penalty boundaries, signed cap/hash
    tampering, no additional sensitivity for reused beta coordinates, Gaussian
    cross terms and canonical ties. Full DSLite/central-fit evidence is recorded
    separately by the shared family harness; these algebra tests do not claim
    execution of the production MPC or noise producer.
14. The postprocessing boundary accepts only finite, exactly representable
    integer common-lattice coordinates. Negative integer noise values remain
    valid; fractional raw coordinates fail with the fixed transcript-safe
    error. Public final objectives remain ordinary binary64 postprocessing.
