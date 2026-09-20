# Layer 1 — mathematics (synthetic, no DataSHIELD)

2026-09-18. PASS for the current certified piecewise profile identities.

- Existing analytic and dense numeric profile evidence: `inst/cross-grid-v2/EXP_REDUCED_CERTIFICATE.md`, `inst/cross-grid-v2/README.md`, and `inst/cross-grid-v2/admission_certificate.json`. The profile and admission certificate hashes are pinned in both packages.
- `Rscript inst/cross-grid-v2/validate_layered_math.R ..`: 20 independent synthetic grids per family, n=2000, six covariates, two candidates around known coefficients. The test-only Go integer oracle evaluates the frozen f50/f100 source encoding with the production certified profile. R independently evaluates the binomial/Poisson family deviance plus the saturated-model constant; an independent mpmath implementation evaluates the exact f50 inputs at 80 decimal digits. All 80 candidate losses are within the analytic per-row error plus lattice-rounding tolerance. Maximum total-loss errors versus high precision are 0.002533 (binomial) and 0.000567 (Poisson); the R and high-precision references differ by at most 1.73e-11.
- Per-instance results (errors, tolerance, caps-derived sensitivities, pooled GLM convergence only): `inst/cross-grid-v2/layer1-objective-evidence.json`. No synthetic source rows or private seed material are included in the report.
- Earlier V1 sensitivity and V2 profile-admission tests remain separate evidence for adjacency multipliers, exact cap construction, and rejection of changed profile/cap/signature metadata. The reported mathematical L2 norm is rounded upward by the admitted contract before production calibration.

This layer does not claim MPC, production noise, or remote lifecycle validation.
