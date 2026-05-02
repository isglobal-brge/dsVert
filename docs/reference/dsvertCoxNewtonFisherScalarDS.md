# Compute scalar share of Fisher term (after Beaver round 2)

After k2BeaverVecmulR2DS has produced the share of z = a .\* b into
cox_n_Beaver_Z_fp, this helper multiplies z elementwise by the plaintext
weight (W1 for first Fisher term, W2 for the second) and returns the
scalar share sum. Caller aggregates both parties.

## Usage

``` r
dsvertCoxNewtonFisherScalarDS(weight_key = c("W1cum", "W2"), session_id = NULL)
```

## Arguments

- weight_key:

  "W1" or "W2".

- session_id:

  MPC session id.

## Value

list(scalar_share_fp = 8-byte base64).
