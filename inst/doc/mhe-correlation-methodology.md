# Privacy-Preserving Correlation using Multiparty Homomorphic Encryption

## 1. Introduction

This document describes the mathematical foundation and implementation of privacy-preserving correlation computation for vertically partitioned data using Homomorphic Encryption (HE).

### 1.1 The Problem

In federated learning with **vertical partitioning**, different servers hold different variables (columns) for the same set of observations (rows):

```
Server A (Hospital 1)          Server B (Hospital 2)
┌─────────────────────┐       ┌─────────────────────┐
│ Patient  Age   BMI  │       │ Patient  Glucose BP │
│ P001     45    28.5 │       │ P001     98     120 │
│ P002     52    31.2 │       │ P002     105    135 │
│ P003     38    24.8 │       │ P003     92     118 │
│ ...      ...   ...  │       │ ...      ...    ... │
└─────────────────────┘       └─────────────────────┘
        X_A (n × p_A)                X_B (n × p_B)
```

**Goal**: Compute the full correlation matrix across ALL variables without:
- Any server seeing another server's raw data
- The client being able to reconstruct individual observations

### 1.2 Why Standard Approaches Fail

The correlation matrix for combined data X = [X_A | X_B] requires computing:

```
        ┌───────────────────────────────┐
        │  Cor(X_A, X_A)  Cor(X_A, X_B) │
  R  =  │                               │
        │  Cor(X_B, X_A)  Cor(X_B, X_B) │
        └───────────────────────────────┘
```

The diagonal blocks (Cor(X_A, X_A) and Cor(X_B, X_B)) are **easy** - each server can compute them locally.

The off-diagonal block Cor(X_A, X_B) is **hard** because it requires:

```
Cor(X_A, X_B) = (Z_A)ᵀ Z_B / (n-1)
```

where Z_A and Z_B are the standardized (centered and scaled) versions of X_A and X_B.

This cross-product **requires access to both datasets at the observation level**.

---

## 2. Mathematical Foundation

### 2.1 Correlation as Inner Products

For standardized data (mean=0, std=1), the Pearson correlation between variables i and j is:

```
ρᵢⱼ = Σₖ zₖᵢ · zₖⱼ / (n-1) = ⟨zᵢ, zⱼ⟩ / (n-1)
```

where zᵢ is the standardized column vector for variable i.

For the cross-correlation matrix between server A (variables 1..p_A) and server B (variables 1..p_B):

```
G_AB = Z_Aᵀ · Z_B

where:
  G_AB[i,j] = Σₖ Z_A[k,i] · Z_B[k,j]  (inner product of columns)
```

This is a matrix of size p_A × p_B.

### 2.2 Homomorphic Encryption Approach

**Key Insight**: We can compute inner products homomorphically!

If we have:
- Enc(z_B) = encrypted vector from server B
- z_A = plaintext vector from server A

We can compute:
```
Enc(z_A · z_B) = z_A ⊙ Enc(z_B)     (element-wise cipher-plaintext multiplication)
Enc(⟨z_A, z_B⟩) = ΣReduce(Enc(z_A · z_B))   (sum all slots)
```

The result is an **encrypted inner product** that can only be decrypted with collaboration from ALL parties.

### 2.3 CKKS Scheme

We use the CKKS (Cheon-Kim-Kim-Song) homomorphic encryption scheme because:

1. **Approximate arithmetic**: Designed for real numbers (not just integers)
2. **SIMD operations**: Can pack multiple values in one ciphertext
3. **Efficient**: Supports both addition and multiplication

CKKS encodes a vector of real numbers into polynomial coefficients:

```
[x₁, x₂, ..., xₙ] → polynomial m(X) → encrypted ciphertext ct
```

Operations on ciphertexts correspond to element-wise operations on the encoded vectors.

### 2.4 Security Model

**Threshold Decryption**: The secret key is split among all servers.

```
sk = sk_A + sk_B + ... + sk_N  (conceptually)
```

- Each server holds only their share skᵢ
- Decryption requires ALL shares
- The client coordinates but CANNOT decrypt alone

**What each party sees**:
| Party | Sees | Cannot See |
|-------|------|------------|
| Server A | X_A, Enc(X_B) | X_B values |
| Server B | X_B | X_A values |
| Client | Enc(G_AB), final G_AB | Individual observations |

---

## 3. The Protocol

### 3.1 Setup Phase (Once per session)

```
┌──────────────────────────────────────────────────────────────┐
│                    KEY GENERATION                            │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│   Server A              Client              Server B         │
│      │                    │                    │             │
│      │◄── RequestSetup ───┤─── RequestSetup ──►│             │
│      │                    │                    │             │
│   Generate              (waits)             Generate         │
│   (sk_A, pk_A)                             (sk_B, pk_B)      │
│      │                    │                    │             │
│      │─── pk_A ──────────►│◄────── pk_B ───────│             │
│      │                    │                    │             │
│      │              Combine:                   │             │
│      │         cpk = Combine(pk_A, pk_B)       │             │
│      │         evk = GenEvalKeys()             │             │
│      │                    │                    │             │
│      │◄─── cpk, evk ──────┤────── cpk, evk ───►│             │
│      │                    │                    │             │
│   Store:               Store:              Store:            │
│   sk_A, cpk, evk      cpk, evk           sk_B, cpk, evk      │
│   (can encrypt,       (can encrypt,      (can encrypt,       │
│    partial decrypt)    CANNOT decrypt)    partial decrypt)   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 3.2 Cross-Product Computation

```
┌──────────────────────────────────────────────────────────────┐
│              COMPUTING G_AB = Z_Aᵀ · Z_B                     │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│   Server A              Client              Server B         │
│      │                    │                    │             │
│      │                    │◄── Enc(Z_B, cpk) ──│             │
│      │                    │   (encrypted       │             │
│      │                    │    standardized    │             │
│      │                    │    data)           │             │
│      │                    │                    │             │
│      │◄── Enc(Z_B) ───────│                    │             │
│      │   (client relays   │                    │             │
│      │    but cannot      │                    │             │
│      │    decrypt!)       │                    │             │
│      │                    │                    │             │
│   For each column pair (i,j):                  │             │
│   ┌────────────────────────┐                   │             │
│   │ z_Aᵢ = Z_A[:, i]       │                   │             │
│   │ enc_z_Bⱼ = Enc(Z_B)[:, j]                  │             │
│   │                        │                   │             │
│   │ // Element-wise multiply                   │             │
│   │ enc_prod = z_Aᵢ ⊙ enc_z_Bⱼ                 │             │
│   │                        │                   │             │
│   │ // Sum all elements    │                   │             │
│   │ enc_dot = ΣReduce(enc_prod)                │             │
│   │                        │                   │             │
│   │ G_AB_enc[i,j] = enc_dot│                   │             │
│   └────────────────────────┘                   │             │
│      │                    │                    │             │
│      │── Enc(G_AB) ──────►│                    │             │
│      │                    │                    │             │
└──────────────────────────────────────────────────────────────┘
```

### 3.3 Threshold Decryption

```
┌──────────────────────────────────────────────────────────────┐
│              DECRYPTING G_AB                                 │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│   Server A              Client              Server B         │
│      │                    │                    │             │
│      │◄── Enc(G_AB) ──────┤─── Enc(G_AB) ─────►│             │
│      │   (request partial │   (request partial │             │
│      │    decryption)     │    decryption)     │             │
│      │                    │                    │             │
│   Compute:                │                Compute:          │
│   share_A =               │                share_B =         │
│   PartialDec(Enc(G_AB),   │                PartialDec(       │
│              sk_A)        │                Enc(G_AB), sk_B)  │
│      │                    │                    │             │
│      │─── share_A ───────►│◄───── share_B ─────│             │
│      │                    │                    │             │
│      │              Combine:                   │             │
│      │         G_AB = Fuse(share_A, share_B)   │             │
│      │                    │                    │             │
│      │              Now client has G_AB        │             │
│      │              (p_A × p_B matrix)         │             │
│      │              but NOT raw data!          │             │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 3.4 Assembling the Full Correlation Matrix

```
┌─────────────────────────────────────────────────────────────┐
│              FINAL ASSEMBLY                                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Server A computes locally: G_AA = Z_Aᵀ · Z_A              │
│   Server B computes locally: G_BB = Z_Bᵀ · Z_B              │
│                                                             │
│   Client receives:                                          │
│   - G_AA from Server A (p_A × p_A)                          │
│   - G_BB from Server B (p_B × p_B)                          │
│   - G_AB via HE protocol (p_A × p_B)                        │
│                                                             │
│   Client assembles:                                         │
│                                                             │
│        ┌────────────────────────────┐                       │
│        │    G_AA    │     G_AB      │                       │
│   G =  │  (local)   │    (HE)       │                       │
│        ├────────────┼───────────────┤                       │
│        │   G_ABᵀ    │     G_BB      │                       │
│        │   (HE)     │   (local)     │                       │
│        └────────────────────────────┘                       │
│                                                             │
│   Correlation matrix:                                       │
│        R = G / (n - 1)                                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Implementation Details

### 4.1 CKKS Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| LogN | 14 | Ring dimension 2¹⁴ = 16384 |
| LogScale | 40 | Precision ~40 bits |
| MaxSlots | 8192 | Max values per ciphertext |
| Security | 128-bit | Post-quantum secure |

### 4.2 Encoding Strategy

For a data matrix Z with n rows and p columns:

**Option A: Row-packed** (used for small n)
```
Each ciphertext contains one row: [z₁₁, z₁₂, ..., z₁ₚ, 0, 0, ...]
```

**Option B: Column-packed** (used for inner products)
```
Each ciphertext contains one column: [z₁ⱼ, z₂ⱼ, ..., zₙⱼ, 0, 0, ...]
```

We use **column-packed** encoding because:
- Inner product of two columns = element-wise multiply + sum-reduce
- Efficient use of SIMD slots

### 4.3 Computational Complexity

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Encryption per column | O(n · log n) | NTT operations |
| Cipher-plain multiply | O(n · log n) | Per column pair |
| Sum-reduce | O(log n) | Tree reduction |
| Total for G_AB | O(p_A · p_B · n · log n) | All column pairs |

### 4.4 Communication Complexity

| Transfer | Size |
|----------|------|
| Enc(Z_B) from B to A | ~350 KB per column |
| Enc(G_AB) from A to client | ~350 KB per element |
| Partial decryptions | ~175 KB per element per server |

---

## 5. Security Analysis

### 5.1 What is Protected

✅ **Individual observations**: No party ever sees raw data from another server
✅ **Cross-server relationships at individual level**: Cannot determine if patient P001's age correlates with their glucose
✅ **Reconstruction attacks**: Client cannot reconstruct X_A or X_B from G_AB alone

### 5.2 What is Revealed

⚠️ **Aggregate statistics**: The correlation matrix R is revealed to the client
⚠️ **Marginal statistics**: Means and standard deviations (used for standardization) - though these could also be computed via secure aggregation

### 5.3 Collusion Resistance

| Colluding Parties | Can They Decrypt? |
|-------------------|-------------------|
| Client alone | ❌ No (has no sk shares) |
| Client + Server A | ❌ No (missing sk_B) |
| Client + Server B | ❌ No (missing sk_A) |
| Server A + Server B | ❌ No (need client to orchestrate) |
| All parties | ✅ Yes (by design) |

---

## 6. References

1. Cheon, J.H., Kim, A., Kim, M., Song, Y. (2017). "Homomorphic Encryption for Arithmetic of Approximate Numbers". ASIACRYPT 2017.

2. Mouchet, C., Troncoso-Pastoriza, J., Bossuat, J.P., Hubaux, J.P. (2021). "Multiparty Homomorphic Encryption from Ring-Learning-with-Errors". PETS 2021.

3. Froelicher, D., et al. (2021). "Truly privacy-preserving federated analytics for precision medicine with multiparty homomorphic encryption". Nature Communications.

4. Lattigo Library: https://github.com/tuneinsight/lattigo
