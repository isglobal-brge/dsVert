# Layer 3 — DP selection

IN PROGRESS. The authenticated production release route is implemented.
Small real two-authority API releases already reproduce the production-noise
oracle bit for bit (see LAYER2_V2.md), including a K3 diagnostic. The n2000
120-selection/12-release campaign is running; no aggregate selection agreement,
loss-gap statistic or completed matrix is claimed until its evidence validator
passes.

The binding remaining matrix is 20 sticky-independent signed grids per family
per epsilon in {1,4,8}, n=2000, delta=2^-100 on the same-noise oracle path,
followed by at least two real two-authority releases per (family,epsilon)
through the two-peer DSLite client harness (12 releases), bit-for-bit equal to
the corresponding oracle releases. Test-only nonlinear circuit runs are not
counted as any of those releases.

The two family-specific fused-kernel/joint-Laplace tests at epsilon=4 are small
synthetic net.Pipe composition tests. They are neither selection statistics nor
DataSHIELD wiring releases and are not counted toward either validation matrix.
