# dsVert — DataSHIELD Server Package for Vertically Partitioned Data

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![R-CMD-check](https://github.com/isglobal-brge/dsVert/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/isglobal-brge/dsVert/actions/workflows/R-CMD-check.yaml)
[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](NEWS.md)

## Overview

**dsVert** is a server-side DataSHIELD package for privacy-preserving statistical analysis on **vertically partitioned federated data**. Each server holds different features (columns) for the same observations (rows). No server sees another's raw data.

All computation uses **Ring63 / Ring127 Beaver MPC** — pure fixed-point arithmetic with additive secret sharing — combined with **DCF wide-spline** non-linear link functions, **OT-Beaver** triple generation, and **ECDH-PSI** record alignment. No observation-level data is ever disclosed.

Pair with the client-side companion package [**dsVertClient**](https://github.com/isglobal-brge/dsVertClient).

## Protocols (v1.1.0)

| Family | Methods | Output |
|---|---|---|
| **PSI** | ECDH blind relay (P-256), Ed25519 identity pinning | Common record set |
| **GLM** (gaussian / binomial / poisson) | Ring63/127 Beaver + DCF wide-spline + L-BFGS, with offset / weights / IPW | Coefficients, SE, p-values, deviance |
| **Cox PH** | Reverse-cumsum reformulation, sort-permutation relay, Newton path A/B (Ring127) | β, SE, partial log-lik |
| **Cox K=2 discrete-time** | Allison 1982 / Andreux 2020 pooled-logistic with Aliasgari-Blanton 2013 share-mask gating | β, SE |
| **Negative Binomial** | iid-µ profile MLE, Method-of-Moments (Anscombe / Saha-Paul), full-regression θ via Ring127 NR-LOG share-domain primitive (Goldschmidt 1964 + Pugh 2004) | β, SE, θ |
| **Multinomial** | OVR + softmax-anchor; joint Newton via DCF exp + reciprocal + Beaver vecmul on per-patient eta_k / mu_k shares (Bohning-bounded) | (K−1)·p coefficient matrix |
| **Ordinal (proportional odds)** | BLUE pool + threshold correction (McCullagh 1980); joint Newton (Tutz 1990 §3.2 block-diagonal + McCullagh §2.5 closed-form H_θθ) | β, θ_k, SE |
| **LMM (random intercept + slopes)** | Laird-Ware GLS closed form, REML/ML, Pinheiro-Bates §2.4.2 within-between ANOVA variance components, K=2 and K=3 | β, σ², σ_b², ICC |
| **GEE** | Working correlation (exchangeable / AR1) + sandwich SE | β, robust SE |
| **GLMM (binomial Laplace)** | Per-cluster inner PIRLS + outer moment-match (stretch deliverable) | β, σ_b² |
| **Correlation** | Ring63 Beaver cross-products | p × p matrix |
| **PCA** | Eigendecomposition of correlation | Loadings, eigenvalues |
| **LASSO / penalised GLM** | Post-hoc soft-threshold; one-step quadratic-surrogate; FISTA proximal-gradient on normal equations; AIC / BIC / EBIC λ selector | Sparse β, support |
| **IPW / propensity** | Two-stage propensity logit + weighted outcome GLM | Adjusted β |
| **Multiple imputation** | Server-local FCS + Rubin pooling client-side | Pooled β, SE |
| **Descriptive / contingency** | Histogram-based quantiles, two-way χ² via Beaver dot product on one-hot shares | Counts, p-values, summaries |

## Architecture

```
Client (analyst)                    Servers (data holders)
┌──────────────┐                   ┌──────────────────────┐
│ ds.vertGLM() │──── DataSHIELD ──→│ Ring63/Ring127 shares│
│ ds.vertCox() │    (HTTP/REST)    │ Beaver matvec        │
│ ds.vertLMM() │                   │ DCF wide-spline      │
│ ds.psiAlign()│←── p aggregates ──│ OT-Beaver triples    │
│ ds.vertNB()  │   (gradients,     │ Ed25519 verification │
│ ds.vertCor() │    deviance)      │ X25519 + AES-256-GCM │
└──────────────┘                   └──────────────────────┘
```

**What the client sees**: p-dimensional gradient aggregates, correlation scalars, deviance (1 scalar), per-cluster BLUPs, χ² statistics. No individual observations.

**What each server sees**: its own data + random additive Ring shares of other servers' data. Cannot reconstruct without all shares.

## Security

| Property | Guarantee |
|---|---|
| Observation-level disclosure | Zero |
| Beaver triples | Server-generated (client never sees) |
| Transport encryption | X25519 + AES-256-GCM (transport-encrypt) |
| Identity verification | Ed25519 signed peer transport keys (require_trusted_peers) |
| Dealer rotation | Different dealer each iteration (K ≥ 3 → rotation; K = 2 → fixed dealer) |
| Collusion threshold | (K−1)/K servers needed to recover any plaintext |
| Ring | Ring63 (frac_bits = 20) for legacy; Ring127 (frac_bits = 50) for STRICT closure (Catrina-Saxena 2010) |

## Go Binary (`dsvert-mpc`)

Standalone binary providing the Ring63 / Ring127 MPC kernels: DCF wide-spline (sigmoid / exp / reciprocal / log-sum-exp), Beaver triple generation, OT-Beaver dishonest-majority triples, transport encryption (X25519 + AES-256-GCM), Ed25519 identity verification, and Catrina-Saxena 2010 fixed-point fp50 ULP truncation. Pure Go, no external crypto libraries beyond `golang.org/x/crypto`.

Per-platform binaries ship under `inst/bin/{darwin-amd64,darwin-arm64,linux-amd64,windows-amd64}/`.

## Installation

```bash
# 1. Build the Go runtime (one-off; per-platform binaries already shipped)
cd inst/dsvert-mpc
go build -o dsvert-mpc .
GOOS=linux GOARCH=amd64 go build -o ../bin/linux-amd64/dsvert-mpc .
# repeat for darwin-amd64, darwin-arm64, windows-amd64 if cross-building

cd ../..

# 2. Build + install the R package
R CMD build --no-build-vignettes .
R CMD INSTALL dsVert_1.1.0.tar.gz
```

## DataSHIELD method registration

Either include `dsVert` in the Opal profile via `dsadmin::install_local_package`, or register the methods explicitly through `opalr::dsadmin.set_method` — the full list of `AggregateMethods:` and `AssignMethods:` is in `DESCRIPTION` (~140 methods).

## Validation

R CMD check: 0 ERRORs, 0 NOTEs, 1 WARNING (intentional `inst/bin/{platform}/dsvert-mpc` Go runtime binaries — unavoidable for the dual-package R + Go architecture).

`testthat`: 88 / 88 PASS. Go test (`dsvert-mpc`): full suite passes in ~2 s.

## License

MIT — see [LICENSE](LICENSE.md).

## Citation

See `paper/jbhi_dsvert.tex` (IEEE J-BHI submission r2.5) for the full validation table and theoretical bounds. Per-method theoretical floors (Catrina-Saxena fp50, McCullagh-Agresti L1, Bohning, Therneau survival) cited in the paper §V.A.
