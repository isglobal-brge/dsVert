# Apply registered weights to the current mu and y shares

Scale this server's mu share (ss\$secure_mu_share) AND its y share
(ss\$k2_y_share_fp) element-wise by the registered weights vector. After
both DCF parties apply this, the reconstructed residual r' = mu' - y'
equals w \* (mu - y) = w \* r, so the subsequent Beaver matrix-vector
gradient X^T r' is the weighted gradient. No Beaver rounds required:
element-wise scaling of a share by a publicly-known vector is local.

## Usage

``` r
k2ApplyWeightsDS(session_id = NULL)
```

## Arguments

- session_id:

  Character. GLM session identifier.

## Value

`list(applied = TRUE)`
