# dsVert - DataSHIELD Server Functions for Vertically Partitioned Data

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

**dsVert** is a server-side DataSHIELD package that enables privacy-preserving statistical analysis on **vertically partitioned federated data**. In vertical partitioning, different data sources hold different variables (columns) for the same set of observations (rows).

This package implements:
- **ECDH-PSI Record Alignment**: Privacy-preserving record matching using Elliptic Curve Diffie-Hellman Private Set Intersection (P-256). Unlike SHA-256 hashing, PSI prevents dictionary attacks on identifiers.
- **Multiparty Homomorphic Encryption (MHE)**: Threshold-decryption based cross-server correlation and encrypted-label GLM gradients using the CKKS scheme (Lattigo v6)
- **Share-Wrapping (Transport Encryption)**: X25519 + AES-256-GCM transport encryption for partial decryption shares, eliminating client exposure to raw shares
- **GLM Secure Routing**: End-to-end transport-encrypted individual-level vector exchange between servers, with the client handling only safe aggregates and opaque blobs
- **Protocol Firewall**: SHA-256 ciphertext registry with one-time-use authorization to prevent decryption oracle attacks
- **Block Coordinate Descent**: Distributed fitting of Generalized Linear Models (3 families)
- **Model Diagnostics**: Deviance calculation for model evaluation
- **Legacy Record Alignment**: SHA-256 hash-based alignment (deprecated, use PSI)

## Architecture

The package has a two-layer architecture: R functions handle DataSHIELD protocol logic, and a compiled Go binary (`mhe-tool`) handles all cryptographic operations (CKKS encryption, P-256 elliptic curve math, X25519 transport encryption).

```
R functions (server-side DS methods)  →  Go binary (mhe-tool)
       ↓                                         ↓
  JSON file I/O via system2()           Lattigo v6 CKKS + crypto/elliptic
                                        X25519 + AES-256-GCM transport layer
                                        SHA-256 ciphertext registry
```

Each R function serializes its input as JSON, calls the `mhe-tool` binary via `system2()`, and parses the JSON output. File-based I/O (not pipes) is used because CKKS ciphertexts can be hundreds of KB.

## Server-Side Functions

### ECDH-PSI Record Alignment (Blind Relay)

| Function | Type | Description |
|----------|------|-------------|
| `psiInitDS` | Aggregate | Generate X25519 transport keypair; load pre-shared keys if configured |
| `psiStoreTransportKeysDS` | Aggregate | Store peer transport PKs; validate against pinned keys if configured |
| `psiMaskIdsDS` | Aggregate | Hash IDs to P-256 points, multiply by random scalar (points stored locally, NOT returned) |
| `psiExportMaskedDS` | Aggregate | Encrypt stored masked points under a target server's transport PK |
| `psiProcessTargetDS` | Aggregate | Decrypt ref points, double-mask them, mask own IDs, encrypt own points under ref's PK |
| `psiDoubleMaskDS` | Aggregate | Decrypt target points, double-mask with stored scalar, encrypt under target's PK (one-shot per target) |
| `psiMatchAndAlignDS` | Assign | Decrypt double-masked own points, match against stored ref points, reorder data |
| `psiSelfAlignDS` | Assign | Self-align reference server (identity) |
| `psiGetMatchedIndicesDS` | Aggregate | Return matched reference indices for intersection |
| `psiFilterCommonDS` | Assign | Filter to multi-server intersection; clean up all PSI state |

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
| `mheAuthorizeCTDS` | Aggregate | Protocol Firewall: register ciphertext for decryption |
| `mheCleanupDS` | Aggregate | Clean up all MHE state (keys, ciphertexts, blobs) |

### Share-Wrapping & Transport Encryption

| Function | Type | Description |
|----------|------|-------------|
| `mheStoreTransportKeysDS` | Aggregate | Store X25519 transport PKs from other servers |
| `mhePartialDecryptWrappedDS` | Aggregate | Compute transport-encrypted partial decryption share |
| `mheStoreWrappedShareDS` | Aggregate | Relay wrapped share to fusion server (chunked) |
| `mheFuseServerDS` | Aggregate | Server-side fusion: unwrap shares, aggregate, DecodePublic |
| `mheStoreBlobDS` | Aggregate | Generic blob storage with chunking support |

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

### GLM Secure Routing

| Function | Type | Description |
|----------|------|-------------|
| `glmCoordinatorStepDS` | Aggregate | Coordinator (label server) IRLS + encrypted (mu,w,v) distribution |
| `glmSecureGradientDS` | Aggregate | Compute encrypted gradient from transport-encrypted mu/w/v |
| `glmSecureBlockSolveDS` | Aggregate | BCD block update with transport-encrypted eta output |
| `glmSecureDevianceDS` | Aggregate | Server-side deviance computation (no eta leak to client) |

### Utilities

| Function | Type | Description |
|----------|------|-------------|
| `mheAvailable` | Aggregate | Check if mhe-tool binary is available |
| `mheVersion` | Aggregate | Get mhe-tool version |
| `base64_to_base64url` | Utility | Convert base64 to URL-safe base64 |

## Security Model

### ECDH-PSI Record Alignment (Blind Relay)

The PSI protocol uses P-256 elliptic curve scalar multiplication for privacy-preserving record matching, with a **blind-relay** architecture that prevents the client from seeing or manipulating raw EC points.

**Core security properties:**

- **Dictionary attack resistance**: Unlike SHA-256 hashing, an attacker cannot pre-compute hashes for plausible IDs. Masked points are indistinguishable from random group elements without the server's secret scalar.
- **Scalar confidentiality**: Each server's random P-256 scalar never leaves the server.
- **Unlinkability (DDH assumption)**: The client cannot link single-masked points across servers.
- **Blind relay**: All EC point exchanges between servers are transport-encrypted (X25519 + AES-256-GCM ECIES). The client relays **opaque encrypted blobs** it cannot read, decrypt, or forge.
- **PSI Firewall (FSM)**: A server-side state machine enforces strict phase ordering. Functions can only be called in the correct sequence, and `psiDoubleMaskDS` is **one-shot per target** — each target server's points can only be double-masked once. This prevents OPRF oracle attacks.

**What the client sees vs. what it cannot see:**

| Data | Client visibility |
|------|------------------|
| EC masked points {alpha*H(id)} | Encrypted blob (opaque) |
| EC double-masked points {alpha*beta*H(id)} | Encrypted blob (opaque) |
| Target masked points {beta*H(id)} | Encrypted blob (opaque) |
| Matched reference indices | Integer set (safe aggregate) |
| Common intersection indices | Integer set (safe aggregate) |
| Observation counts | Scalar (safe aggregate) |

#### Two Security Modes

dsVert supports two security modes for PSI transport key exchange, configured via DataSHIELD R options:

##### Mode 1: Semi-Honest (default)

- **Ephemeral X25519 keys** are generated per session
- Client mediates key exchange between servers
- Protects against **passive eavesdropping** but NOT active MITM by the client
- Suitable for trusted DataSHIELD deployments where the client application is trusted
- **No configuration needed** — this is the default behavior

##### Mode 2: Full MITM-Resistant (pre-shared keys)

- **Persistent X25519 keypairs** are pre-configured on each server by the administrator
- Servers validate client-provided PKs against pre-configured peers during `psiStoreTransportKeysDS`
- Any PK mismatch triggers a **MITM detection error** — the client may have substituted keys
- In this mode, the server uses its pre-configured peer PKs (not the client-provided ones), so the client cannot add, remove, or modify peers
- Suitable for **untrusted or multi-tenant environments**

#### PSI Firewall: Phase Ordering FSM

The server enforces strict phase ordering to prevent protocol abuse:

```
Reference server:                     Target server:
  (none) → init:    psiInitDS()         (none) → init:              psiInitDS()
  init → masked:    psiMaskIdsDS()      init → target_processed:    psiProcessTargetDS()
  masked → masked:  psiExportMaskedDS() target_processed → matched: psiMatchAndAlignDS()
  masked → masked:  psiDoubleMaskDS()
                    (one-shot per target)
```

Any attempt to call functions out of order is rejected with a firewall error. This prevents a malicious client from:
- Calling `psiDoubleMaskDS` multiple times for the same target (OPRF oracle)
- Calling matching functions before masking is complete
- Skipping the transport key exchange phase

### MHE Threshold Decryption

The MHE protocol uses **threshold decryption**: data encrypted under the Collective Public Key (CPK) can only be decrypted when ALL servers cooperate by providing their partial decryption shares.

- **Server privacy**: Each server's raw data never leaves the server. Other servers only see encrypted ciphertexts.
- **Client privacy**: The client (researcher) cannot decrypt any ciphertext alone. It only sees partial decryption shares (useless individually) and the final aggregate statistic (correlation coefficients).
- **Collusion resistance**: Even K-1 colluding servers cannot decrypt without the K-th server's key share.

### Transport Encryption (X25519 + AES-256-GCM)

dsVert includes an ECIES-pattern transport encryption layer using X25519 key agreement and AES-256-GCM authenticated encryption. Each server generates an ephemeral X25519 key pair. Sender and recipient derive a shared secret via X25519 Diffie-Hellman, then encrypt the payload with AES-256-GCM. Ephemeral keys provide **forward secrecy**: compromising a long-term key does not reveal past transport-encrypted payloads.

Transport encryption is used in two contexts:

1. **Share-Wrapping** (correlation/decryption protocol)
2. **GLM Secure Routing** (individual-level vector exchange)

### Share-Wrapping

Non-fusion servers **wrap** their partial decryption shares under the fusion server's X25519 public key before returning them to the client. The client receives only opaque encrypted blobs and relays them to the fusion server. The fusion server unwraps all received shares, computes its own partial decryption share locally, aggregates them, and returns the sanitized plaintext (e.g., correlation coefficients). The client never sees raw partial decryption shares.

### GLM Secure Routing

The label server acts as **coordinator**: it runs the IRLS update to compute mu, w, and v, then transport-encrypts these vectors end-to-end for each destination server using that server's X25519 public key. The client relays the opaque encrypted blobs. Each non-label server decrypts mu/w/v, computes its encrypted gradient and block update locally, and returns transport-encrypted eta contributions back to the coordinator. The client only handles:

- **Beta vectors** (length p_k, the number of features on server k) -- safe aggregate statistics
- **Opaque encrypted blobs** -- indistinguishable from random bytes without the recipient's X25519 private key

### Protocol Firewall

The Protocol Firewall prevents **decryption oracle attacks**, where a malicious client could submit arbitrary ciphertexts for threshold decryption to extract information beyond the sanctioned protocol.

Each server maintains a **SHA-256 ciphertext registry**. Before any ciphertext can be submitted for partial decryption, it must be explicitly authorized via `mheAuthorizeCTDS`. Authorization is **one-time-use**: once a ciphertext has been decrypted, its registry entry is consumed and the same ciphertext cannot be decrypted again. This ensures the client can only decrypt ciphertexts that were produced as part of the legitimate protocol flow.

## Chunked Transfer Protocol

DataSHIELD's R expression parser imposes a size limit on arguments passed inline in `call()` expressions. Cryptographic objects routinely exceed this limit:

| Object | Typical size | Exceeds limit at |
|--------|-------------|------------------|
| CKKS ciphertexts | 100-300 KB | Always |
| EC points (PSI) | ~44 bytes/ID | n > 100K IDs |
| Galois key shares | ~525 KB each | Always |
| CRP (Common Reference Polynomial) | ~1.6 MB at LogN=14 | LogN >= 14 |
| CT hash batches | ~64 bytes/hash | p_A * p_B > 350 |

dsVert solves this with a **store-and-assemble** pattern via `mheStoreBlobDS`. The client splits large data into 10 KB chunks and sends each chunk in a separate `datashield.aggregate` call. The server auto-assembles them when the last chunk arrives. Downstream functions read the assembled data via `from_storage = TRUE` instead of inline arguments.

```
Client:  split(data, 10KB) → chunk_1, chunk_2, ..., chunk_n
Server:  mheStoreBlobDS(key, chunk_1, 1, n)
         mheStoreBlobDS(key, chunk_2, 2, n)  → auto-assembled on last chunk
         ...
         targetFunction(..., from_storage = TRUE)  ← reads assembled blob
```

All data is base64url-encoded (standard base64 uses `+` and `/`, which the DSOpal expression serializer can misinterpret). This pattern is used uniformly across all protocols (PSI, MHE correlation, GLM) for any data that scales with n, p, or K.

## DataSHIELD Configuration (R Options)

dsVert reads all configuration from R options following the **dsBase two-tier fallback pattern**: `getOption("dsvert.X")` first, then `getOption("default.dsvert.X")`. This allows Opal administrators to override settings per DataSHIELD profile.

### Disclosure Control Options

These options control privacy-preserving disclosure limits. Defaults are set in the package DESCRIPTION and can be overridden per DataSHIELD profile:

| Option | Default | Description |
|--------|---------|-------------|
| `datashield.privacyLevel` | `5` | Minimum observations for any operation |
| `default.nfilter.tab` | `3` | Minimum cell count for binary variables |
| `default.nfilter.glm` | `0.33` | Maximum parameter-to-observation ratio |
| `default.nfilter.subset` | `3` | Minimum subset size for PSI intersection |

### PSI Key Pinning Options (Full MITM-Resistant Mode)

These options enable pre-shared key pinning for MITM-resistant PSI. They are **not set by default** — when absent, the semi-honest mode with ephemeral keys is used.

| Option | Default | Description |
|--------|---------|-------------|
| `dsvert.psi_key_pinning` | `FALSE` | Enable pre-shared key mode |
| `dsvert.psi_sk` | *(not set)* | This server's X25519 secret key (standard base64) |
| `dsvert.psi_pk` | *(not set)* | This server's X25519 public key (standard base64) |
| `dsvert.psi_peers` | *(not set)* | JSON string mapping peer server names to their X25519 PKs |

#### Configuration example (Opal/Rock)

The administrator configures these per-server via the Opal DataSHIELD profile settings (web UI) or via `dsadmin.set_option()`:

```r
# On server1 (e.g., via dsadmin.set_option or Rock .Rprofile):
options(
  dsvert.psi_key_pinning = TRUE,
  dsvert.psi_sk = "W8Jz...base64...==",
  dsvert.psi_pk = "Kp3R...base64...==",
  dsvert.psi_peers = '{"server2":"Ax7Q...==","server3":"Bm9K...==","ref":"Kp3R...=="}'
)
```

The `dsvert.psi_peers` JSON maps server names (as used in the DataSHIELD login) to their X25519 public keys. Include a `"ref"` alias pointing to the reference server's PK.

#### Security of R options in DataSHIELD

Storing secret keys as R options is safe in DataSHIELD because:

1. **The client cannot call `getOption()` remotely** — the DataSHIELD parser (datashield4j) validates every function call in the AST against the registered methods whitelist. `getOption` is not registered.
2. **`listDisclosureSettingsDS()` in dsBase** only returns specific nfilter values, not arbitrary options.
3. **Our registered functions never return the private key** — `psiInitDS()` returns only the public key and a `pinned` boolean.
4. **The Opal admin REST API** can read DataSHIELD options, but requires administrator credentials — the admin is already trusted (they configure the keys).

### Other Options

| Option | Default | Description |
|--------|---------|-------------|
| `dsvert.mhe_tool` | *(not set)* | Path to the mhe-tool binary (fallback: `DSVERT_MHE_TOOL` env var) |

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

## Requirements

- R >= 4.0.0
- digest (for hashing)
- jsonlite (for MHE JSON I/O)
- Go 1.21+ (for building mhe-tool from source)
- A DataSHIELD server environment (Opal/Rock)

## Authors

- David Sarrat González (david.sarrat@isglobal.org)
- Miron Banjac (miron.banjac@isglobal.org)
- Juan R González (juanr.gonzalez@isglobal.org)
