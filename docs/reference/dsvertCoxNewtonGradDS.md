# Return the p_total-vector grad(0) scalar share

grad_c(0) = sum_i delta(i) X_c(i) - sum_i (delta/N)(i) S_c(i) Both terms
are share \* plaintext-at-both elementwise (safe – gives a share of the
product, since both parties multiply the same plaintext into their
share). This helper returns a base64-encoded length-p_total FP
scalar-share vector; the client aggregates the two parties' shares
element-wise via k2-ring63-aggregate.

## Usage

``` r
dsvertCoxNewtonGradDS(session_id = NULL)
```

## Arguments

- session_id:

  MPC session id.

## Value

list(grad_shares_fp = base64 FP vector of length p_total).
