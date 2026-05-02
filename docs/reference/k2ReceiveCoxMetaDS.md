# Receive Cox permutation and event indicator on the peer server

Consume the peer blob previously relayed via `mpcStoreBlobDS`, decrypt,
and store the sort permutation + event indicator FP vector so the local
Cox primitives can apply the same ordering to this server's X share.

## Usage

``` r
k2ReceiveCoxMetaDS(session_id = NULL)
```

## Arguments

- session_id:

  GLM session id.

## Value

list(stored = TRUE, n)
