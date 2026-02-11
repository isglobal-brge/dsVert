# dsVert - DataSHIELD Server Functions for Vertically Partitioned Data

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

**dsVert** is a server-side DataSHIELD package that enables privacy-preserving statistical analysis on **vertically partitioned federated data**. In vertical partitioning, different data sources hold different variables (columns) for the same set of observations (rows).

This package implements:
- **Record Matching**: Secure alignment of records across servers using cryptographic hashing
- **Block SVD**: Distributed singular value decomposition for correlation and PCA
- **Block Coordinate Descent**: Distributed fitting of Generalized Linear Models

## Installation

```r
# Install from GitHub
devtools::install_github("isglobal-brge/dsVert")
```

## Server-Side Functions

| Function | Type | Description |
|----------|------|-------------|
| `hashIdDS` | Aggregate | Hash identifier column using SHA-256 |
| `alignRecordsDS` | Assign | Reorder/subset data to match reference hashes |
| `blockSvdDS` | Aggregate | Compute U*D from SVD for Block SVD algorithm |
| `glmPartialFitDS` | Aggregate | Perform one BCD iteration for GLM fitting |
| `getObsCountDS` | Aggregate | Get observation count for validation |
| `prepareDataDS` | Assign | Prepare data for analysis (subset, standardize) |

## Requirements

- R >= 4.0.0
- digest (for hashing)
- A DataSHIELD server environment (Opal) or DSLite for testing

## Authors

- David Sarrat González (david.sarrat@isglobal.org)
- Miron Banjac (miron.banjac@isglobal.org)
- Juan R González (juanr.gonzalez@isglobal.org)

## References

- van Kesteren, E.J. et al. (2019). Privacy-preserving generalized linear models using distributed block coordinate descent. arXiv:1911.05935.
- Iwen, M. & Ong, B.W. (2016). A distributed and incremental SVD algorithm for agglomerative data analysis on large networks. SIAM Journal on Matrix Analysis and Applications.
