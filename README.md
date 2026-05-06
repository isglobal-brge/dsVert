# dsVert - DataSHIELD Server Package for Vertically Partitioned Data

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](NEWS.md)

## Overview

**dsVert** is the server-side DataSHIELD package for privacy-preserving
analysis on vertically partitioned federated data. Each server holds different
columns for the same aligned records; no server receives another server's raw
features or outcome column.

The analyst-facing API lives in
[**dsVertClient**](https://github.com/isglobal-brge/dsVertClient). This package
ships the server functions registered in Opal/DataSHIELD plus the Go MPC
runtime used by those functions.

## Product Surface

The production DataSHIELD surface is the `AggregateMethods` and
`AssignMethods` list in `DESCRIPTION`. Disclosive or materially suboptimal
historical helpers have been removed from the server namespace or omitted from
method registration when they are low-level safe primitives only.

Diagnostic helpers that could reconstruct session shares, patient-level
working vectors, or legacy Cox rank metadata are not shipped as invocable
routes. Tests assert both the DataSHIELD product surface and the R namespace.

## Methods (v1.1.0)

| Family | Product route |
|---|---|
| PSI / alignment | ECDH-PSI common-record alignment with Ed25519 peer identity pinning |
| GLM | Gaussian, binomial, and Poisson GLM with Ring63/Ring127 Beaver MPC, DCF wide-spline links, offsets, weights, and IPW |
| Cox PH | Non-disclosive Breslow profile route for K=2 and K>=3; K=2 discrete-time pooled-logistic route is also available |
| Negative binomial | iid-mu, Method-of-Moments, and non-disclosive full-regression theta share-domain route |
| Multinomial / ordinal | Joint Newton routes; warm starts are internal only |
| Mixed models | LMM K=2/K>=3, GEE, binomial GLMM-PQL, and binomial GLMM-Laplace with guarded cluster aggregates |
| Penalised / causal / MI | LASSO variants, two-stage IPW, and multiple imputation with Rubin pooling |
| Descriptive / second-order | Descriptives, contingency/chi-square, Fisher helper, correlation, and PCA |

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

**What the client sees**: model-scale aggregates such as gradients, Fisher or
Hessian summaries, guarded cluster summaries, correlation/cross-product
scalars, deviances, and test statistics. No observation-level aggregate is part
of the product surface.

**What each server sees**: its own data + random additive Ring shares of other servers' data. Cannot reconstruct without all shares.

## Security

| Property | Guarantee |
|---|---|
| Observation-level disclosure | Not product-exposed |
| Beaver triples | Server-generated (client never sees) |
| Transport encryption | X25519 + AES-256-GCM (transport-encrypt) |
| Identity verification | Ed25519 signed peer transport keys (require_trusted_peers) |
| Dealer rotation | Different dealer each iteration (K ≥ 3 → rotation; K = 2 → fixed dealer) |
| Collusion threshold | (K−1)/K servers needed to recover any plaintext |
| Ring | Ring63 (frac_bits = 20) and Ring127 (frac_bits = 50) depending on method precision needs |

## Go Runtime (`dsvert-mpc`)

`inst/dsvert-mpc` contains the current Go source for the Ring63/Ring127 MPC
kernels: DCF wide-spline functions, Beaver and OT-Beaver primitives, transport
encryption, identity verification, and fixed-point truncation. Per-platform
runtime binaries ship under
`inst/bin/{darwin-amd64,darwin-arm64,linux-amd64,windows-amd64}/`.

The Go binary intentionally exposes only low-level kernel commands. Product
analysis routes are orchestrated by R DataSHIELD methods, and the safe product
surface is still the `AggregateMethods` list. Commands that would directly
reveal session state, legacy Cox ranks, patient-level working vectors, or
debug snapshots are not part of the Go command surface. A test guards this.

The old experimental `inst/k2-mpc-tool` tree is no longer part of the package;
the maintained implementation is `inst/dsvert-mpc`.

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
R CMD INSTALL "$(ls -t dsVert_*.tar.gz | head -1)"
```

## DataSHIELD method registration

Either include `dsVert` in the Opal profile via `dsadmin::install_local_package`, or register the methods explicitly through `opalr::dsadmin.set_method` — the full list of `AggregateMethods:` and `AssignMethods:` is in `DESCRIPTION` (~140 methods).

## Validation

The server test suite includes a product-surface disclosure check that verifies
legacy patient-level helpers and Cox rank primitives are not listed in
`AggregateMethods`, are not namespace-exported, and are absent from the package
namespace. The Go runtime is tested independently under `inst/dsvert-mpc`.

The executable method evidence is maintained in the client package because the
client vignettes drive the full DSLite workflow. See the
[dsVertClient validation summary](https://isglobal-brge.github.io/dsVertClient/articles/validation_summary.html)
for the current K=2/K>=3 distributed-vs-centralized validation matrix.

## License

MIT - see [LICENSE](LICENSE.md).

## Citation

See `paper/jbhi_dsvert.tex` (IEEE J-BHI submission r2.5) for the full validation table and theoretical bounds. Per-method theoretical floors (Catrina-Saxena fp50, McCullagh-Agresti L1, Bohning, Therneau survival) cited in the paper §V.A.
