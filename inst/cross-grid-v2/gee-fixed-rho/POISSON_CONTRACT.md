# Poisson fixed-rho promotion contract

The promotion target is `poisson_gee`, `staged_fixed_rho_v1`, with signed
analyst-specified **independence rho=0**. The release driver supplies those
parameters explicitly. Exchangeable and AR1 are retained arithmetic options;
successful releases at those options are not prerequisites for this promotion.
The shared Gaussian certified-support issue belongs to the integrator and is
outside this lane's changes.

The real proof cell is n2000/C500/B4/p3/J2, epsilon=8, delta=2^-100, q16,
score clip=1, K=2/3/5 authenticated source owners and two compute/noise
authorities. Outcomes are bounded integer counts in {0,...,4}, with the signed
predictor/candidate bounds ensuring |eta|<=4. Rho is independent of the data
and candidates; the whitening coefficient is not an estimated correlation.

The complete release contains the count and, for each of two candidates,
likelihood plus the upper triangles of bread and clipped-score meat:
1 + 2*(1+10+10) = 43 coordinates. Execution uses authenticated 16/16/11
sampler chunks without changing the complete-vector privacy plan. Recovery
keeps the sticky release identity and geometry; a new attempt uses fresh
cryptography. No prior failed snapshot's private state is migrated.

For per-cluster coordinate caps L_k, add/remove sensitivity is sum(L_k) in L1
and sqrt(sum(L_k^2)) in L2, outward rounded. Replacement/movement uses twice
those bounds. C500 scales maximum coordinates, not sensitivity. The count is
included in the complete noise plan. J4 arithmetic admission does not imply
release capacity: p3/J4 would require 85 coordinates, above the unchanged
51-coordinate sampler limit.

The mirrored contracts are `R/crossgrid_grouped.R` and
`dsVertClient/R/dp_grouped_grid_cross_contract.R`. Both bind certificate
`82df4b2c32f19f0ac248acbd424f079edd5e29546f95e6e3c520c2e2232be3e3`.
Their staged-contract tests cover signed native fields, certificate and
working-correlation tampering, C500 admission, cluster-independent sensitivity,
replacement adjacency, and rejection of estimated or unsupported rho values.
The retained r7 focused run passed 953 combined assertions across both families;
this count is not a Poisson-only total or a real release claim.

The precommitted Poisson n2000 exact count/vector SHA256 is
`3b4cce7f7b713a1f1801e6965821753012865d3d84590b97b8023c3fff7be858`.
It binds the public synthetic oracle, not a DP draw. Each real K2/K3/K5 release
must match it and pass sticky/cold/tamper checks. K2 additionally exercises all
five retained recovery boundaries. Both complete paired suites must pass, with
warnings and skips reviewed.

Capacity is measured at the real proof cell: at most 256,000,000,000 bytes of
R-serialized aggregate RPC traffic and 21,600 seconds through first successful
publication. IPC framing is excluded. The 900-second inactivity and
86,400-second execution leases do not relax that gate. Report the scope as
**p<=3/C<=500 at B4/J2, independence rho=0**, with the measured n2000 endpoint;
do not infer coverage of every intermediate C or larger arithmetic domain.

Promotion remains pending until the retained real-release, recovery, paired,
and capacity evidence passes. This document finalizes scope without changing
package code, signed caps, privacy parameters, or the frozen r7 source.
