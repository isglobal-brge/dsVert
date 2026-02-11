# dsVert - DataSHIELD Server Functions for Vertically Partitioned Data

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

**dsVert** is a server-side DataSHIELD package that enables privacy-preserving statistical analysis on **vertically partitioned federated data**. In vertical partitioning, different data sources hold different variables (columns) for the same set of observations (rows).

This package implements:
- **Record Alignment**: Secure matching of records across servers via cryptographic hashing
- **ID Validation**: Format consistency checks before alignment
- **Multiparty Homomorphic Encryption (MHE)**: Threshold-decryption based cross-server correlation using the CKKS scheme (Lattigo v6)
- **Block Coordinate Descent**: Distributed fitting of Generalized Linear Models
- **Model Diagnostics**: Deviance calculation for model evaluation

## Architecture

The MHE functions follow a two-layer architecture:

```
R wrappers (mheFullProtocol.R)  →  Go binary (mhe-tool)  →  Lattigo v6 CKKS
       ↓                                    ↓
  JSON file I/O                     Threshold decryption
```

Each R function serializes its input as JSON, calls the `mhe-tool` binary via `system2()`, and parses the JSON output. The Go binary uses Lattigo's multiparty module for cryptographic operations.

## Server-Side Functions

### Record Alignment

| Function | Type | Description |
|----------|------|-------------|
| `hashIdDS` | Aggregate | Hash identifier column using SHA-256 |
| `validateIdFormatDS` | Aggregate | Validate identifier format consistency |
| `alignRecordsDS` | Assign | Reorder/subset data to match reference hashes |
| `getObsCountDS` | Aggregate | Get observation count for validation |
| `prepareDataDS` | Assign | Prepare data for analysis (subset, standardize) |

### MHE Threshold Protocol

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

### GLM

| Function | Type | Description |
|----------|------|-------------|
| `glmPartialFitDS` | Aggregate | Perform one BCD iteration for GLM fitting |
| `glmDevianceDS` | Aggregate | Calculate deviance for model evaluation |

### Utilities

| Function | Type | Description |
|----------|------|-------------|
| `mheAvailable` | Aggregate | Check if mhe-tool binary is available |
| `mheVersion` | Aggregate | Get mhe-tool version |
| `base64_to_base64url` | Utility | Convert base64 to URL-safe base64 |

## MHE Security Model

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

- Mouchet, C. et al. (2021). "Multiparty Homomorphic Encryption from Ring-Learning-With-Errors". *Proceedings on Privacy Enhancing Technologies (PETS)*.
- Cheon, J.H. et al. (2017). "Homomorphic Encryption for Arithmetic of Approximate Numbers". *ASIACRYPT 2017*.
- van Kesteren, E.J. et al. (2019). "Privacy-preserving generalized linear models using distributed block coordinate descent". arXiv:1911.03183.
- Lattigo v6: https://github.com/tuneinsight/lattigo
