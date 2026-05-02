# Export own share (complement) to second DCF party

After k2ShareInputDS splits features into (own_share, peer_share), this
function transport-encrypts the own_share for a different recipient.
Used by non-DCF servers to send the complement half to the second DCF
party, ensuring both DCF parties together hold additive shares that sum
to X_k.

## Usage

``` r
glmRing63ExportOwnShareDS(peer_pk, session_id = NULL)
```

## Arguments

- peer_pk:

  Character. Transport PK of the second DCF party (base64url).

- session_id:

  Character or NULL.

## Value

List with encrypted_own_share (base64url).
