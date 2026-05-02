# Receive observation weights from the DCF peer (non-outcome side)

Consume the peer's weights blob previously relayed via `mpcStoreBlobDS`,
decrypt it with this server's transport secret key, and store the
plaintext FP weights vector for subsequent `k2ApplyWeightsDS` calls.
Pairs with `k2SetWeightsDS` on the outcome-holding server.

## Usage

``` r
k2ReceiveWeightsDS(session_id = NULL)
```

## Arguments

- session_id:

  Character. GLM session identifier.

## Value

`list(stored = TRUE, n = length)`
