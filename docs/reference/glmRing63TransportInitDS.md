# Initialize transport keys with Ed25519 identity

Generates X25519 transport keypair + signs it with the server's
persistent Ed25519 identity key for pinned peer verification.

## Usage

``` r
glmRing63TransportInitDS(session_id = NULL)
```

## Arguments

- session_id:

  Character or NULL.

## Value

List with transport_pk, identity_pk, signature (all base64url).
