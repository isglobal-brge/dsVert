# Per-cluster FP sum of a session share vector (LMM exact)

Sum `ss[[share_key]]` within each cluster defined by
`ss$k2_lmm_cluster_ids`, returning one base64 FP scalar share per
cluster. Linear op preserves additive sharing: the two parties' outputs
aggregate (client-side k2-ring63-aggregate) to the per-cluster plaintext
sum.

Aggregates only; no per-patient information returns to the client.

## Usage

``` r
dsvertLMMPerClusterSumDS(share_key, session_id = NULL, frac_bits = 20L)
```

## Arguments

- share_key:

  Session slot holding the n-vector FP share.

- session_id:

  MPC session id.

- frac_bits:

  Ring63 fractional bits (default 20).

## Value

list(per_cluster_fp: K-vector of base64 FP scalars, cluster_sizes,
n_clusters).
