# Layer 3 — DP selection

NOT RUN. An internal fused kernel now exists, but the authenticated production
release route does not, so no oracle/production release-equivalence claim is
possible. No selection agreement, loss-gap statistics or sticky independence
results are claimed.

The binding remaining matrix is 20 sticky-independent signed grids per family
per epsilon in {1,4,8}, n=2000, delta=2^-100 on the same-noise oracle path,
followed by at least two real two-authority releases per (family,epsilon)
through the two-peer DSLite client harness (12 releases), bit-for-bit equal to
the corresponding oracle releases. Test-only nonlinear circuit runs are not
counted as any of those releases.

The two family-specific fused-kernel/joint-Laplace tests at epsilon=4 are small
synthetic net.Pipe composition tests. They are neither selection statistics nor
DataSHIELD wiring releases and are not counted toward either validation matrix.
