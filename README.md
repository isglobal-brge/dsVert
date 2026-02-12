# dsVert - DataSHIELD Server Functions for Vertically Partitioned Data

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

**dsVert** is a server-side DataSHIELD package that enables privacy-preserving statistical analysis on **vertically partitioned federated data**. In vertical partitioning, different data sources hold different variables (columns) for the same set of observations (rows).

This package implements:
- **ECDH-PSI Record Alignment**: Privacy-preserving record matching using Elliptic Curve Diffie-Hellman Private Set Intersection (P-256). Unlike SHA-256 hashing, PSI prevents dictionary attacks on identifiers.
- **Multiparty Homomorphic Encryption (MHE)**: Threshold-decryption based cross-server correlation and encrypted-label GLM gradients using the CKKS scheme (Lattigo v6)
- **Block Coordinate Descent**: Distributed fitting of Generalized Linear Models (5 families)
- **Model Diagnostics**: Deviance calculation for model evaluation
- **Legacy Record Alignment**: SHA-256 hash-based alignment (deprecated, use PSI)

## Architecture

The package has a two-layer architecture: R functions handle DataSHIELD protocol logic, and a compiled Go binary (`mhe-tool`) handles all cryptographic operations (CKKS encryption, P-256 elliptic curve math).

```
R functions (server-side DS methods)  →  Go binary (mhe-tool v1.4.0)
       ↓                                         ↓
  JSON file I/O via system2()           Lattigo v6 CKKS + crypto/elliptic
```

Each R function serializes its input as JSON, calls the `mhe-tool` binary via `system2()`, and parses the JSON output. File-based I/O (not pipes) is used because CKKS ciphertexts can be hundreds of KB.

## Server-Side Functions

### ECDH-PSI Record Alignment

| Function | Type | Description |
|----------|------|-------------|
| `psiMaskIdsDS` | Aggregate | Hash IDs to P-256 points, multiply by random scalar |
| `psiProcessTargetDS` | Aggregate | Double-mask reference points, mask own IDs |
| `psiDoubleMaskDS` | Aggregate | Double-mask received points with stored scalar |
| `psiMatchAndAlignDS` | Assign | Match double-masked sets, reorder data |
| `psiSelfAlignDS` | Assign | Self-align reference server (identity) |
| `psiGetMatchedIndicesDS` | Aggregate | Return matched reference indices for intersection |
| `psiFilterCommonDS` | Assign | Filter to multi-server intersection |

### Legacy Record Alignment (deprecated)

| Function | Type | Description |
|----------|------|-------------|
| `hashIdDS` | Aggregate | Hash identifier column using SHA-256 |
| `validateIdFormatDS` | Aggregate | Validate identifier format consistency |
| `alignRecordsDS` | Assign | Reorder/subset data to match reference hashes |
| `getObsCountDS` | Aggregate | Get observation count for validation |
| `prepareDataDS` | Assign | Prepare data for analysis (subset, standardize) |

### MHE Threshold Protocol (Correlation)

| Function | Type | Description |
|----------|------|-------------|
| `mheInitDS` | Aggregate | Generate secret key and public key share for this party |
| `mheCombineDS` | Aggregate | Combine public key shares into Collective Public Key (CPK) |
| `mheStoreCPKDS` | Aggregate | Store CPK received from the combine step |
| `mheEncryptLocalDS` | Aggregate | Encrypt local data columns under the CPK |
| `mheStoreEncChunkDS` | Aggregate | Store a chunk of an encrypted column (for transfer) |
| `mheAssembleEncColumnDS` | Aggregate | Reassemble encrypted column from chunks |
| `mheCrossProductEncDS` | Aggregate | Compute plaintext * ciphertext element-wise (encrypted result) |
| `mheStoreCTChunkDS` | Aggregate | Store a ciphertext chunk for partial decryption |
| `mhePartialDecryptDS` | Aggregate | Compute partial decryption share using this server's secret key |
| `mheGetObsDS` | Aggregate | Get number of complete observations for variables |
| `localCorDS` | Aggregate | Compute local (within-server) correlation matrix |

### Encrypted-Label GLM Protocol

| Function | Type | Description |
|----------|------|-------------|
| `mheEncryptRawDS` | Aggregate | Encrypt response variable y under CPK (label server) |
| `mheStoreEncYDS` | Aggregate | Store encrypted y on non-label servers |
| `mheGLMGradientDS` | Aggregate | Compute encrypted gradient X_k^T(ct_y - mu) |
| `glmBlockSolveDS` | Aggregate | BCD block update using decrypted gradient |
| `glmPartialFitDS` | Aggregate | Plaintext BCD iteration (label server) |
| `glmStandardizeDS` | Aggregate | Standardize features for BCD convergence |
| `glmDevianceDS` | Aggregate | Calculate deviance for model evaluation |

### Utilities

| Function | Type | Description |
|----------|------|-------------|
| `mheAvailable` | Aggregate | Check if mhe-tool binary is available |
| `mheVersion` | Aggregate | Get mhe-tool version |
| `base64_to_base64url` | Utility | Convert base64 to URL-safe base64 |

## Security Model

### ECDH-PSI Record Alignment

The PSI protocol uses P-256 elliptic curve scalar multiplication for privacy-preserving record matching. Security properties:

- **Dictionary attack resistance**: Unlike SHA-256 hashing, an attacker cannot pre-compute hashes for plausible IDs. Masked points are indistinguishable from random group elements without the server's secret scalar.
- **Scalar confidentiality**: Each server's random P-256 scalar never leaves the server.
- **Unlinkability (DDH assumption)**: The client cannot link single-masked points across servers; it can only determine which double-masked points correspond to the same identifier.

### MHE Threshold Decryption

The MHE protocol uses **threshold decryption**: data encrypted under the Collective Public Key (CPK) can only be decrypted when ALL servers cooperate by providing their partial decryption shares.

- **Server privacy**: Each server's raw data never leaves the server. Other servers only see encrypted ciphertexts.
- **Client privacy**: The client (researcher) cannot decrypt any ciphertext alone. It only sees partial decryption shares (useless individually) and the final aggregate statistic (correlation coefficients).
- **Collusion resistance**: Even K-1 colluding servers cannot decrypt without the K-th server's key share.

## Building the Go Binary

The `mhe-tool` binary must be compiled for each target platform:

```bash
cd inst/mhe-tool

# Build for all platforms
make all

# Or build for a specific platform
make linux          # Linux amd64
make darwin-arm64   # macOS Apple Silicon
make darwin-amd64   # macOS Intel
make windows        # Windows amd64
```

Binaries are placed in `inst/bin/<platform>/mhe-tool`.

### Platform Support

| Platform | Architecture | Binary Path |
|----------|-------------|-------------|
| macOS | arm64 (Apple Silicon) | `inst/bin/darwin-arm64/mhe-tool` |
| macOS | amd64 (Intel) | `inst/bin/darwin-amd64/mhe-tool` |
| Linux | amd64 | `inst/bin/linux-amd64/mhe-tool` |
| Windows | amd64 | `inst/bin/windows-amd64/mhe-tool.exe` |

## Supported GLM Families

| Family | Link | Use Case |
|--------|------|----------|
| `gaussian` | Identity | Continuous outcomes (linear regression) |
| `binomial` | Logit | Binary outcomes (logistic regression) |
| `poisson` | Log | Count data |
| `Gamma` | Log | Positive continuous data (costs, times) |
| `inverse.gaussian` | Log | Positive continuous with high variance |

## Requirements

- R >= 4.0.0
- digest (for hashing)
- jsonlite (for MHE JSON I/O)
- Go 1.21+ (for building mhe-tool from source)
- A DataSHIELD server environment (Opal/Rock)

## Authors

- David Sarrat Gonzalez (david.sarrat@isglobal.org)
- Miron Banjac (miron.banjac@isglobal.org)
- Juan R Gonzalez (juanr.gonzalez@isglobal.org)

## References

- De Cristofaro, E. & Tsudik, G. (2010). "Practical Private Set Intersection Protocols with Linear Complexity". *FC 2010*.
- Mouchet, C. et al. (2021). "Multiparty Homomorphic Encryption from Ring-Learning-With-Errors". *Proceedings on Privacy Enhancing Technologies (PETS)*.
- Cheon, J.H. et al. (2017). "Homomorphic Encryption for Arithmetic of Approximate Numbers". *ASIACRYPT 2017*.
- van Kesteren, E.J. et al. (2019). "Privacy-preserving generalized linear models using distributed block coordinate descent". arXiv:1911.03183.
- Lattigo v6: https://github.com/tuneinsight/lattigo
