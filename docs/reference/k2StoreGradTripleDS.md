# Store gradient Beaver triple (Ring63 FP format)

Store gradient Beaver triple (Ring63 FP format)

## Usage

``` r
k2StoreGradTripleDS(session_id = NULL, grad_triple_key = "k2_grad_triple_fp")
```

## Arguments

- session_id:

  Character. Active MPC session identifier.

- grad_triple_key:

  Blob-store key under which the encrypted Beaver triple was deposited.
  Defaults to "k2_grad_triple_fp" for backwards compatibility with
  single-shot GLM. Multi-round consumers (multinom- joint,
  ordinal-joint) MUST pass a per-class / per-iter key (e.g.
  paste0("k2_grad_triple_fp_class\_", ki)) to avoid blob-key collision
  across the K-1 classes within an outer Newton iter and between
  consecutive outer iters. This eliminates a race-prone pattern
  documented in ABY3 Sec.IV.D (Mohassel-Rindal 2018 CCS) and MP-SPDZ
  Programs/Source/Multiplications.hpp where pool isolation is
  per-multiplication, not per-pool.
