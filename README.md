# dsVert — DataSHIELD Server Package for Vertically Partitioned Data

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

**dsVert** is a server-side DataSHIELD package for privacy-preserving statistical analysis on **vertically partitioned federated data**. Each server holds different features (columns) for the same observations (rows). No server sees another's raw data.

All computation uses **Ring63 Beaver MPC** — pure fixed-point arithmetic with additive secret sharing. No observation-level data is ever disclosed.

## Protocols

| Protocol | Method | Output |
|----------|--------|--------|
| **PSI** | ECDH blind relay (P-256) | Common record set |
| **GLM** (3 families) | Ring63 Beaver + DCF wide spline + L-BFGS | Coefficients, SE, p-values |
| **Correlation** | Ring63 Beaver cross-products | p x p matrix |
| **PCA** | Eigen decomposition of correlation | Loadings, eigenvalues |

## Architecture

```
Client (analyst)                    Servers (data holders)
┌──────────────┐                   ┌──────────────────────┐
│ ds.vertGLM() │──── DataSHIELD ──→│ Ring63 FP shares     │
│ ds.vertCor() │    (HTTP/REST)    │ Beaver matvec        │
│ ds.psiAlign()│←── p aggregates ──│ DCF wide spline      │
│ ds.vertPCA() │    (gradients)    │ Transport encryption │
└──────────────┘                   └──────────────────────┘
```

**What the client sees**: p-dimensional gradient aggregates (sums over n observations), correlation scalars, deviance (1 scalar). No individual observations.

**What each server sees**: its own data + random additive Ring63 shares of other servers' data. Cannot reconstruct without all shares.

## Security

| Property | Guarantee |
|----------|-----------|
| Observation-level disclosure | Zero |
| Beaver triples | Server-generated (client never sees) |
| Transport encryption | X25519 + AES-256-GCM |
| Dealer rotation | Different dealer each iteration (K>=4) |
| Collusion threshold | (K-1)/K servers needed |

## Go Binary (dsvert-mpc)

Standalone 4.1 MB binary with 21 commands for Ring63 MPC, DCF, Beaver, PSI, and transport encryption. Pure Go, no external crypto libraries.

## Installation

```bash
cd inst/dsvert-mpc
go build -o dsvert-mpc .
GOOS=linux GOARCH=amd64 go build -o ../bin/linux-amd64/dsvert-mpc .
cd ../..
R CMD build --no-build-vignettes .
R CMD INSTALL dsVert_2.1.0.tar.gz
```
