# Clause 5 arithmetic boundary — 2026-09-18

The old whole-cluster GC traffic bound does not apply to the revised design.
This note is an integration/correctness audit, not a new failed traffic gate.

## Implemented split

`groupedScalarCompile(name, count)` admits 1..32 q16 scalar evaluations,
validates every reconstructed argument privately, substitutes an in-domain
argument before evaluation, and outputs fresh additive shares of all values
plus one aggregate validity bit. Any invalid argument zeros the whole batch.
It uses the existing certified coefficients and exactly the existing integer
rounding. Profile and range-reduction certificates are unchanged. Guards and
masks are included in the measured AND count; compilation retains all runner
caps. It is an internal emitter, not a source reader or a release capability.

`groupedShareBlockSums` performs exact modular sums for fixed PUBLIC padded
blocks and columns, on one authority's shares at a time, without changing
fractional scale or ring width. Invoke after the once-per-release private
permutation AND secure complete-case masking. It also sums already securely
computed squares, but does not compute those squares. Its public geometry
cannot substitute for private segment-start controls. Bounds must prove no
signed overflow of the reconstructed result before interpreting a sum.

Compact transport imports only the two engine files from Step-2 0006f1a,
explicitly requested by Addendum 2. Legacy wrappers retain their original
framing. Grouped compact runners bind topology, source and contract using the
primitive session and authenticated record layer. They do not manufacture
signed source claims, persisted chunk receipts or release authorization.

## Operations that are not local linear maps

For x=x0+x1 (mod 2^w), x^2=x0^2+2*x0*x1+x1^2. Squaring each share and
adding loses the cross term: shares 3 and 4 of 7 yield 25 rather than 49,
even modulo 256. The sum of squares can be locally reduced only after the
cross-owner products have been securely computed. A quadratic is nonlinear
as a function of its inputs, although it requires no transcendental profile.

The random-intercept coefficient rho/(1+n_c*rho) is also private: rho is
public but n_c includes remote complete-case validity. For rho=1, private
counts 1 and 2 give coefficients 1/2 and 1/3. Use a secure table selection or
certified reciprocal, then secure multiplication by the squared segment sum.
Do not open the count or use the grouping owner's pre-completeness count.

Other required secure operations:

- GLMM: outcome times shared eta; private validity masks; maximum selection
  for stable quadrature log-sum-exp; final nonnegative clipping and rounding.
- GEE: feature-times-residual and feature cross-products, variance factors,
  private-mask-dependent exchangeable/AR1 weights, score clipping, and the
  outer product of the clipped private cluster score. Public beta/rho does
  not make these operands public. Sharing private-owner cleartext products
  does not compute products involving the other owner's private operands.
- Every family: exact ties-even rescaling and ring conversion. Local rounding
  of shares 1 and 1 divided by 2 gives 0+0 rather than round(2/2)=1. Zero-
  extending Ring32 shares into Ring192 also needs a carry correction; it is
  not a valid local change of ring. Keep the frozen f50/f100/q64 ABI.
- Secret segment resets multiply an accumulator by a secret start bit. Use
  fixed public B-slot blocks after oblivious packing, or a secure scan; a
  host-language branch on the private bit is forbidden.

## Available engine and missing interface

The existing `k2_beaver_vecmul.go` and `k2_beaver_vecmul_ring127.go` generate
both triple shares at a dealer. Either computing authority acting as that
dealer learns the masks used in opened Beaver differences; it is not the
required non-colluding two-authority preprocessing. The relay cannot become
a third trusted authority. `k2_beaver_google_ring127_ops.go` explicitly gives
approximate local truncation with a rare wrap failure, not the frozen exact
nearest-even operation. Neither helper is an interchangeable implementation.

A valid route is dealer-free two-party secure products (for example checked
OT-generated cross products/triples), plus exact rescaling, width conversion,
comparison/masking and authenticated state. These have nonzero traffic even
when they use no GC gates. Alternatively retain measured short exact GC
arithmetic kernels, but that needs a clarified interpretation of the stated
scalar-only GC restriction. No new arithmetic protocol is certified by this
note. Its receipt interface must compose with Step 2's authenticated fusion.

The grouped lane has requested clarification whether it or an upstream lane
owns this backend. Step 2 at 8b6c7bf records fusion as unfinished. Until the
backend and receipt interface are fixed, a claimed measured full-release
capacity would omit required protocol traffic and would be invalid. Scalar
measurements alone cannot admit a signed (n,grid) envelope.

## Addendum 3 resolution (2026-09-18)

The ownership question above is resolved: this lane implements the dealer-free
checked-OT backend in 80aee12. Do not reuse the historical "missing backend"
statement as a current blocker. LMM components use exact Ring192 products and
carry-correct two-limb final accumulation; GH5 composition has share-side sums
and scalar-only profiles. GEE moment boundaries are implemented, but private
whitening remains unfinished. INTEGRATION_GROUPED.md specifies the current
backend receipt interface and external authenticated-fusion dependency.
