# Consume a relayed Beaver vecmul triple

Per-party aggregate. Decrypts the session blob
`"k2_beaver_vecmul_triple"` (relayed by the client from the dealer's
[`k2BeaverVecmulGenTriplesDS`](https://isglobal-brge.github.io/dsVert/reference/k2BeaverVecmulGenTriplesDS.md))
using this server's transport secret key and stores the base64 triple
payload under `ss$k2_beaver_vecmul_triple` for subsequent round-1 /
round-2 calls.

## Usage

``` r
k2BeaverVecmulConsumeTripleDS(session_id = NULL)
```

## Arguments

- session_id:

  MPC session id.

## Value

list(stored = TRUE).
