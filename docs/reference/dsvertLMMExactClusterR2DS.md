# LMM cross-server exact: per-cluster r^2 aggregate

After the Beaver vecmul has populated `k2_lmm_exact_r2_share` (share of
r^2) on the outcome server (where cluster IDs live plaintext), sum
within each cluster to produce per-cluster scalar FP shares and return
them. Client aggregates the two parties' outputs via
`k2-ring63-aggregate` to reconstruct per-cluster RSS.

For the non-outcome party the cluster-ID info is NOT broadcast; this
helper runs ONLY on the outcome server, and on the peer side we return a
vector of per-cluster partial sums produced from the peer's own r^2
share by summing against the SAME cluster indicator vector (which must
be broadcast client-side via mpcStoreBlobDS as well; see the companion
broadcast helper).

## Usage

``` r
dsvertLMMExactClusterR2DS(
  data_name,
  cluster_col,
  r2_key = "k2_lmm_exact_r2_share",
  session_id = NULL,
  frac_bits = 20L
)
```

## Arguments

- data_name:

  Aligned data frame.

- cluster_col:

  Cluster column.

- r2_key:

  Session slot holding the r^2 share (default
  `"k2_lmm_exact_r2_share"`).

- session_id:

  MPC session id.

- frac_bits:

  Integer. Fixed-point fractional-bit precision (e.g. 20 for Ring63, 50
  for Ring127).

## Value

list(per_cluster_fp – K vector of base64 FP scalars, cluster_sizes,
n_clusters).
