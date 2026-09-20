# H.4/H.5 alpha scope at cycle17

The retained v3 whitening path accepts signed fixed rho. H.4 requests a
candidate-independent moment estimate. No estimator/reference or additional
privacy contract arrived in this cycle; the question was asked again while
release and Cox work continued. This is an unresolved contract, not an
arithmetic/protocol impossibility. No BLOCKED file or ULTRA escalation.

The concrete decisions needed before estimated-alpha admission are:

1. Specify the residuals/mean fit used once, the pair/cluster weighting and
   denominator; define empty clusters, zero variance, missing rows and padding.
2. Specify the admitted alpha interval, projection/rounding and denominator
   encoding. Bind the estimated-alpha stage and its predecessor receipts to
   the signed numeric contract, separate from signed-fixed-rho-v3-predecessor.
3. Decide whether estimated alpha/whitening coefficients remain private or
   become public. Public data-dependent coefficients require their own privacy
   justification/accounting; the current fixed-public-rho producer provides
   none. A private estimate requires a private coefficient-consumption path.
4. Bound the released likelihood/bread/clipped-meat vector with alpha allowed
   to change after one patient's change. The existing fixed-rho local-cluster
   sensitivity cannot silently cover changes to every cluster's coefficients.

These are scope decisions. No estimator, privacy cost or sensitivity is invented.
The existing fixed-rho source/worker/reader component proofs remain valid in
that scope; no signed estimated-alpha smoke or n2000 launch is claimed.
