# Query this server's identity public key

Returns the Ed25519 identity PK. Used by admins to discover PKs for
configuring trusted_peers lists across a consortium.

## Usage

``` r
dsvertIdentityPkDS()
```

## Value

List with identity_pk (base64url).
