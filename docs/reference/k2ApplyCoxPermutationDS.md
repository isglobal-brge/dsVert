# Apply the Cox sort permutation to this server's X share

Reorder the cached X share (ss\$k2_x_share_fp) and peer X share
(ss\$k2_peer_x_share_fp) in place so subsequent eta computations operate
on the ascending-time ordering.

## Usage

``` r
k2ApplyCoxPermutationDS(session_id = NULL)
```

## Arguments

- session_id:

  GLM session id.

## Value

list(applied = TRUE)
